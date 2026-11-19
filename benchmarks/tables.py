#!/usr/bin/env python3
import argparse
import json
import math
from pathlib import Path
import statistics

import harness
import schedule

BASE = harness.BASE


def result_key(result):
    key = (result["backend"], result["case"], result["profile"])
    if schedule.lattice_wide(result["backend"], result["case"]):
        return key + (result.get("representation"), result.get("key_switch_requested"))
    return key


def percentile(values, fraction):
    values = sorted(values)
    if not values:
        raise ValueError("empty statistic")
    position = (len(values) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    return values[lower] + (values[upper] - values[lower]) * (position - lower)


def summarize(values):
    if not values:
        return {"n": 0, "status": "not_applicable"}
    return {"n": len(values), "median": statistics.median(values),
            "q1": percentile(values, 0.25), "q3": percentile(values, 0.75),
            "iqr": percentile(values, 0.75) - percentile(values, 0.25),
            "min": min(values), "max": max(values)}


def phases(result):
    keygen = result.get("keygen_ms")
    install = result.get("key_install_ms")
    return {"eval_ms": result["eval_ms"], "decrypt_ms": result["decrypt_ms"],
            "decrypt_batch_ms": result["decrypt_batch_ms"],
            "encryption_ms": [result["encryption_ms"]], "keygen_ms": [] if keygen is None else [keygen],
            "key_install_ms": [] if install is None else [install],
            "setup_ms": [] if keygen is None else [keygen + (install or 0.0)],
            "e2e_ms": [result["e2e_ms"]], "copy_reset_ms": result["copy_reset_ms"]}


def cell_tables(records):
    groups = {}
    for result in records:
        groups.setdefault(result_key(result), []).append(result)
    rows = []
    for key, group in sorted(groups.items()):
        backend, case, profile = key[:3]
        row = {"backend": backend, "case": case, "profile": profile, "status": "MEASURED",
               "logical_outputs": group[0]["logical_outputs"],
               "physical_input_ciphertexts": group[0]["physical_input_ciphertexts"],
               "encryption_key_model": group[0]["encryption_key_model"],
               "evidence": [r["evidence_path"] for r in group],
               "measurement_units": "n counts timed batches, not decrypted outputs, decrypt_ms and output_bytes are whole-request values per evaluation"}
        for phase in ("eval_ms", "decrypt_ms", "decrypt_batch_ms", "encryption_ms", "keygen_ms", "key_install_ms",
                      "setup_ms", "e2e_ms", "copy_reset_ms"):
            values = [value for r in group for value in phases(r)[phase]]
            row[phase] = summarize(values)
            if phase == "eval_ms":
                row["batch_size"] = group[0]["batch_size"]
                by_key = {}
                for r in group:
                    key_id = Path(r["evidence_path"]).stem.split("-fixture-")[0]
                    by_key.setdefault(key_id, []).extend(r[phase])
                row["per_key_median_ms"] = {k: statistics.median(v) for k, v in sorted(by_key.items())}
        for phase in ("output_bytes", "batch_output_bytes", "input_bytes", "output_ciphertext_bytes",
                      "output_levels", "output_scales"):
            values = [value for r in group for value in (r[phase] if isinstance(r.get(phase), list) else [r[phase]] if phase in r else [])]
            row[phase] = summarize(values)
        row["peak_rss_kib"] = summarize([r["execution"]["peak_rss_kib"] for r in group])
        row["peak_rss_measurement"] = (f"adapter getrusage at exit, {group[0]['process_peak_rss_unit']}, "
                                       "whole process including setup/validation, not eval-only allocation, sampled supervision RSS is separate")
        for field in ("public_key_bytes", "relinearization_key_bytes", "rotation_key_bytes", "server_key_bytes"):
            values = [r[field] for r in group if field in r and r[field] is not None]
            if values:
                row[field] = summarize(values)
        row["worst_absolute_error"] = max(r["validation"]["worst_absolute_error"] for r in group)
        row["worst_relative_error"] = max(r["validation"]["worst_relative_error"] for r in group)
        if backend == "ckks":
            row["maintenance"] = "explicit RescaleInPlace after each ct-ct multiply, one spare output-accuracy level for multiplicative workloads, D64 uses six reduction rotations"
        if backend == "pvac":
            row["security_status"] = "concrete whole-construction security unestablished, ciphertext grows with depth, no established public compact refresh"
        if backend == "tfhe64":
            row["width_scope"] = "bounded-input 64-bit-container sensitivity, not arbitrary full-width equivalence"
        if group[0]["fixture"].get("wide", False):
            row["terminal_contract"] = "canonical exact clear client answer, not an encrypted canonical-field-output guarantee"
            for field in ("representation", "key_switch_requested", "key_switch_technique", "radix", "crt_channels", "input_container", "output_container", "ring_dimensions"):
                if group[0].get(field) is not None:
                    row[field] = group[0][field]
        rows.append(row)
    return rows


def session_records(pass_name, cell, key):
    directory = schedule.cell_directory(pass_name, cell)
    expected_fixture_ids = schedule.pass_fixture_ids(cell, pass_name)
    paths = [directory / f"key-{key}-fixture-{fixture_id}.json" for fixture_id in expected_fixture_ids]
    failure_path = directory / f"key-{key}.failure.json"
    if all(path.exists() for path in paths):
        if failure_path.exists():
            raise ValueError(f"both successful and failed session evidence exist: {directory}")
        records = [harness.load_json(path) for path in paths]
        expected_key = schedule.key_process_id(pass_name, cell, key)
        for index, (record, path) in enumerate(zip(records, paths)):
            expected_fixture_id = expected_fixture_ids[index]
            if record.get("fixture_index") != index or record["fixture"].get("fixture_id") != expected_fixture_id:
                raise ValueError(f"session fixture identity mismatch {path}")
            if record.get("status") != "PASS" or record.get("key_process_id") != expected_key:
                raise ValueError(f"invalid session record {path}")
            if record.get("profile") != cell["profile"] or record.get("requested_repetitions") != cell["repetitions"]:
                raise ValueError(f"session profile/repetition mismatch {path}")
            if record.get("batch_size") != cell["batch_size"]:
                raise ValueError(f"session batch mismatch {path}")
            if record.get("requested_warmups") != 1:
                raise ValueError(f"session warmup mismatch {path}")
            harness.validate(record, record["fixture"], check_identity=True)
            record["evidence_path"] = str(path.relative_to(BASE))
        if len({record["fixture_index"] for record in records}) != len(cell["fixture_ids"]):
            raise ValueError("duplicated session fixture index")
        setup = [record for record in records if record.get("keygen_ms") is not None]
        if len(setup) != 1 or setup[0]["fixture_index"] != 0:
            raise ValueError("incorrect setup count in session")
        return records, None
    if failure_path.exists():
        failure = harness.load_json(failure_path)
        if failure.get("status") not in ("TIMEOUT", "MEMORY_LIMIT", "ERROR"):
            raise ValueError(f"invalid failure status: {failure_path}")
        expected_key = schedule.key_process_id(pass_name, cell, key)
        manifest = harness.manifest_identity()
        if failure.get("key_process_id") != expected_key or failure.get("fixture_ids") is None:
            raise ValueError("failure session identity mismatch")
        if set(failure["fixture_ids"]) != set(cell["fixture_ids"]):
            raise ValueError("failure fixture coverage mismatch")
        if failure.get("harness_identity") != manifest["combined_sha256"] or failure.get("execution_identity") != manifest["execution_identity"]:
            raise ValueError("stale failure identity")
        if failure.get("schedule_sha256") != harness.sha256_file(BASE / "results/pilot-schedule.json"):
            raise ValueError("stale failure schedule")
        return [], failure
    raise ValueError(f"missing scheduled session: {directory} key={key}")


def load_pass(name, schedule, allow_incomplete=False):
    records, failures = [], []
    for cell in schedule["schedule"]:
        for key in range(cell["keys"]):
            session, failure = session_records(name, cell, key)
            records.extend(session)
            if failure:
                failures.append(failure)
    receipt = harness.load_json(BASE / "results" / f"{name}-complete.json")
    expected_sessions = sum(cell["keys"] for cell in schedule["schedule"])
    if receipt.get("key_sessions") != expected_sessions:
        raise ValueError(f"{name}: incomplete pass receipt")
    manifest = harness.manifest_identity()
    if receipt.get("harness_sha256") != manifest["combined_sha256"] or receipt.get("execution_identity") != manifest["execution_identity"]:
        raise ValueError(f"{name}: stale execution identity")
    if receipt.get("schedule_sha256") != harness.sha256_file(BASE / "results/pilot-schedule.json"):
        raise ValueError(f"{name}: stale schedule identity")
    expected_status = "PASS" if not failures else "FAILURES_PRESENT"
    if receipt.get("status") != expected_status or len(receipt.get("failures", [])) != len(failures):
        raise ValueError(f"{name}: pass receipt status mismatch")
    return records, failures, receipt


def compare(forward, reverse):
    f = {result_key(row): row for row in forward}
    r = {result_key(row): row for row in reverse}
    result = []
    for key in sorted(set(f) | set(r)):
        left = f.get(key, {"status": "MISSING_OR_FAILED", "eval_ms": {}, "output_bytes": {}})
        right = r.get(key, {"status": "MISSING_OR_FAILED", "eval_ms": {}, "output_bytes": {}})
        disagreement = None
        if left.get("eval_ms", {}).get("n", 0) and right.get("eval_ms", {}).get("n", 0):
            a, b = left["eval_ms"]["median"], right["eval_ms"]["median"]
            disagreement = abs(a - b) / max(1e-15, (abs(a) + abs(b)) / 2)
        result.append({"backend": key[0], "case": key[1], "profile": key[2],
                       "representation": key[3] if len(key) > 3 else None,
                       "key_switch_requested": key[4] if len(key) > 4 else None,
                       "forward_status": left["status"], "reverse_status": right["status"],
                       "forward_eval_median_ms": left.get("eval_ms", {}).get("median"),
                       "reverse_eval_median_ms": right.get("eval_ms", {}).get("median"),
                       "relative_pass_disagreement": disagreement,
                       "forward_output_bytes_median": left.get("output_bytes", {}).get("median"),
                       "reverse_output_bytes_median": right.get("output_bytes", {}).get("median")})
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-incomplete", action="store_true")
    args = parser.parse_args()
    schedule = harness.load_json(BASE / "results/pilot-schedule.json")
    manifest = harness.manifest_identity()
    if schedule.get("harness_sha256") != manifest["combined_sha256"] or schedule.get("execution_identity") != manifest["execution_identity"]:
        raise ValueError("schedule is not bound to the current harness and executable")
    if args.allow_incomplete:
        document = {"status": "INCOMPLETE_DIAGNOSTIC_ONLY", "schedule": schedule,
                    "note": "coverage and pass receipts were not checked, not a final benchmark table"}
        harness.write_json(BASE / "results/tables.json", document)
        print(json.dumps(document, indent=2, allow_nan=False))
        return
    forward, forward_failures, forward_receipt = load_pass("forward", schedule)
    reverse, reverse_failures, reverse_receipt = load_pass("reverse", schedule)
    forward_rows, reverse_rows = cell_tables(forward), cell_tables(reverse)
    failures = forward_failures + reverse_failures
    status = "PASS" if not failures else "FAILURES_PRESENT"
    document = {"status": status,
                "method": "median and linear-interpolation quartiles over timed batches, repeated timings share keys and are not independent key draws",
                "task": "small bounded programs below 32768 plus declared wide terminal exact-integer programs, CKKS small approximate panel only",
                "venue": f"single recorded {manifest['platform']} host, 1-worker and 4-worker profiles, no cross-hardware ratio",
                "caveats": ["PVAC concrete whole-construction security unestablished, ciphertext growth and lack of established public refresh must accompany every PVAC timing",
                            "PVAC encryption uses the secret key, OpenFHE uses a public key, TFHE uses the client key, these are not identical encryption services",
                            "TFHE64 rows are bounded-input container sensitivity, not proof of full-width arithmetic equivalence",
                            "wide rows return a canonical exact clear client answer and do not establish an encrypted canonical-field-output service",
                            "CKKS has no reviewed exact-integer adapter in the wide panel",
                            "no cross-scheme ratio is generated, a future ratio smaller than relevant pass disagreement is not interpretable"],
                "forward": forward_rows, "reverse": reverse_rows,
                "forward_failures": forward_failures, "reverse_failures": reverse_failures,
                "forward_receipt": forward_receipt, "reverse_receipt": reverse_receipt,
                "comparison": compare(forward_rows, reverse_rows)}
    harness.write_json(BASE / "results/tables.json", document)
    print(json.dumps({"status": status, "output": str(BASE / "results/tables.json"),
                      "forward_cells": len(forward_rows), "reverse_cells": len(reverse_rows),
                      "failures": len(failures), "ratios_generated": False}, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
