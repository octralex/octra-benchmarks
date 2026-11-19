#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile

import export_samples
import harness
import manifest
import schedule
import tables
import verify_tables

BASE = harness.BASE
R3_IDENTITY = "de645cef684a0416a1531d4380574b39bff8b34da681279ab6ee6e57a2c0af7e"
R3_EXECUTION = "a576d62df1d8208044fdd6fd6589e4c880dff353695867593fe5da79ff3f7eaf"


def synthetic_invoke(argv, stdin, log_stem, timeout=1800):
    case = argv[argv.index("--case") + 1]
    output = Path(argv[argv.index("--output") + 1])
    repetitions = int(argv[argv.index("--repetitions") + 1])
    batch_size = int(argv[argv.index("--batch") + 1])
    fixture_count = int(argv[argv.index("--fixture-count") + 1])
    threads = int(argv[argv.index("--threads") + 1])
    lines = stdin.splitlines()
    if len(lines) != 2 * fixture_count:
        raise ValueError("synthetic session input count mismatch")
    fixtures = [item for item in harness.load_json(harness.BASE / "fixtures.json") if item["case"] == case]
    darwin = sys.platform == "darwin"
    peak_bytes = 16 * 1024 * 1024
    rusage = {
        "process_peak_rss_bytes": peak_bytes,
        "process_peak_rss_unit": harness.expected_rss_unit(),
        "process_peak_rss_raw": peak_bytes if darwin else peak_bytes // 1024,
        "process_peak_rss_raw_unit": "bytes" if darwin else "KiB",
        "process_peak_rss_source": "adapter_exit",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    raw_records = []
    for index in range(fixture_count):
        x = [int(value) for value in lines[2 * index].split(",")]
        y = [int(value) for value in lines[2 * index + 1].split(",")]
        matches = [fixture for fixture in fixtures if fixture["x"] == x and fixture["y"] == y]
        if len(matches) != 1:
            raise ValueError("synthetic session input does not identify one canonical fixture")
        fixture = matches[0]
        expected = [int(value) for value in fixture["expected"]]
        full_values = [value % (1 << 128) for value in expected]
        limbs = [(value & ((1 << 64) - 1), value >> 64) for value in full_values]

        def values(prefix, count):
            lo, hi = prefix + "values_lo", prefix + "values_hi"
            return lo, [limb[0] for limb in limbs] * count, hi, [limb[1] for limb in limbs] * count

        measured = values("", repetitions * batch_size)
        warmup = values("warmup_", 1)
        e2e = values("e2e_", 1)
        base = 1.0 if case == "S-add" else 2.0
        record = {
            "backend": "pvac",
            "case": case,
            "logical_outputs": len(expected),
            "physical_input_ciphertexts": len(x) + len(y),
            "encryption_key_model": "secret key",
            "batch_size": batch_size,
            "fixture_index": index,
            "fixture_count": fixture_count,
            "eval_ms": [base + fixture["fixture_id"] / 10 + repetition / 100 for repetition in range(repetitions)],
            "decrypt_ms": [0.2 + repetition / 100 for repetition in range(repetitions)],
            "decrypt_batch_ms": [0.2 + repetition / 100 for repetition in range(repetitions)],
            "copy_reset_ms": [0.01 for _ in range(repetitions)],
            "warmup_eval_ms": [base],
            "warmup_decrypt_ms": [0.2],
            "encryption_ms": 0.3,
            "e2e_ms": base + 0.5,
            "keygen_ms": 3.0 if index == 0 else None,
            "key_install_ms": 1.0 if index == 0 else None,
            "kernel_selection_ms": 0.0,
            "expected_value_count": repetitions * batch_size * len(expected),
            "kernel": "gf2_conv_pmull" if darwin else "gf2_conv_clmul",
            "runtime_toeplitz_id": 2 if darwin else 1,
            "runtime_toeplitz_id_at_completion": 2 if darwin else 1,
            "input_bytes": 64,
            "public_key_bytes": 1024,
            "output_bytes": [128 + fixture["fixture_id"] for _ in range(repetitions)],
            "batch_output_bytes": [128 + fixture["fixture_id"] for _ in range(repetitions)],
            "output_ciphertext_bytes": [],
            "output_levels": [],
            "output_scales": [],
            measured[0]: measured[1],
            measured[2]: measured[3],
            warmup[0]: warmup[1],
            warmup[2]: warmup[3],
            e2e[0]: e2e[1],
            e2e[2]: e2e[3],
        }
        raw_records.append(record)
    output.write_text("".join(json.dumps(record, allow_nan=False) + "\n" for record in raw_records))
    harness.write_json(Path(str(output) + ".rusage.json"), rusage)
    execution = {
        "command": ["synthetic-engine"] + argv,
        "backend_command": argv,
        "returncode": 0,
        "wall_seconds": 0.01 * fixture_count,
        "peak_rss_kib": 4096,
        "peak_rss_unit": "synthetic sampled supervision RSS",
        "affinity": None,
        "timed_out": False,
        "memory_exceeded": False,
        "stdout": str(log_stem.with_suffix(".stdout")),
        "stderr": str(log_stem.with_suffix(".stderr")),
        "host": {"scope": "self-contained synthetic engine invocation"},
        "synthetic_fixture_inputs": len(raw_records),
        "synthetic_threads": threads,
    }
    harness.write_json(log_stem.with_suffix(".execution.json"), execution)
    return execution


def synthetic_control():
    original = {
        "harness.BASE": harness.BASE,
        "schedule.BASE": schedule.BASE,
        "tables.BASE": tables.BASE,
        "export_samples.BASE": export_samples.BASE,
        "export_samples.RESULTS": export_samples.RESULTS,
        "verify_tables.RESULTS": verify_tables.RESULTS,
        "harness.invoke": harness.invoke,
        "manifest.current_fingerprint": manifest.current_fingerprint,
    }
    (BASE / "results").mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="two-pass-control-", dir=BASE / "results") as temporary:
        root = Path(temporary)
        shutil.copyfile(BASE / "fixtures.json", root / "fixtures.json")
        parameters = {"scope": "self-contained synthetic PVAC parameter identity"}
        harness.write_json(root / "results/pvac-parameters.json", parameters)
        combined = hashlib.sha256(b"pvac self-contained two-pass control harness").hexdigest()
        execution = hashlib.sha256(b"pvac self-contained two-pass control execution").hexdigest()
        harness.write_json(root / "results/harness-manifest.json", {
            "schema": harness.SCHEMA,
            "combined_sha256": combined,
            "execution_identity": execution,
            "fixtures_sha256": harness.sha256_file(root / "fixtures.json"),
            "pvac_parameters_sha256": hashlib.sha256(harness.canonical(parameters).encode()).hexdigest(),
            "platform": sys.platform,
        })
        cells = [{
            "backend": "pvac",
            "case": case,
            "profile": 1,
            "representation": "coef-binary",
            "key_switch": "AUTO",
            "keys": 1,
            "fixture_ids": [2, 3],
            "repetitions": 2,
            "batch_size": 1,
            "timeout_seconds": 1800,
        } for case in ("S-add", "S-mul")]
        document = {
            "status": "frozen",
            "harness_sha256": combined,
            "execution_identity": execution,
            "schedule": cells,
            "scope": "self-contained synthetic records, not a pilot or benchmark schedule",
        }
        harness.write_json(root / "results/pilot-schedule.json", document)
        try:
            harness.BASE = root
            schedule.BASE = root
            tables.BASE = root
            export_samples.BASE = root
            export_samples.RESULTS = root / "results"
            verify_tables.RESULTS = root / "results"
            harness.invoke = synthetic_invoke
            manifest.current_fingerprint = lambda: combined

            for pass_name in ("forward", "reverse"):
                profile_seconds = {1: 0.0, 4: 0.0}
                for cell in cells:
                    ordered = dict(cell)
                    ordered["fixture_ids"] = schedule.pass_fixture_ids(cell, pass_name)
                    result = schedule.run_session(pass_name, ordered, 0)
                    if result.get("status") != "PASS":
                        raise RuntimeError(f"synthetic {pass_name} session failed: {result}")
                    profile_seconds[cell["profile"]] += result["session_wall_seconds"]
                harness.write_json(root / "results" / f"{pass_name}-complete.json", {
                    "status": "PASS",
                    "pass": pass_name,
                    "key_sessions": len(cells),
                    "profile_execution_seconds": profile_seconds,
                    "harness_sha256": combined,
                    "execution_identity": execution,
                    "schedule_sha256": harness.sha256_file(root / "results/pilot-schedule.json"),
                    "failures": [],
                })

            forward, forward_failures, forward_receipt = tables.load_pass("forward", document)
            reverse, reverse_failures, reverse_receipt = tables.load_pass("reverse", document)
            if forward_failures or reverse_failures:
                raise RuntimeError("synthetic two-pass records contain failures")
            if len(forward) != 4 or len(reverse) != 4:
                raise RuntimeError("synthetic two-pass record coverage mismatch")
            comparison = tables.compare(tables.cell_tables(forward), tables.cell_tables(reverse))
            if {(row["backend"], row["case"]) for row in comparison} != {("pvac", "S-add"), ("pvac", "S-mul")}:
                raise RuntimeError("synthetic two-pass comparison cells mismatch")
            for cell in cells:
                records, failure = tables.session_records("reverse", cell, 0)
                if failure is not None:
                    raise RuntimeError(f"synthetic reverse session failed: {cell['case']}")
                actual = [record["fixture"]["fixture_id"] for record in records]
                if actual != [3, 2]:
                    raise RuntimeError(f"synthetic reverse fixture order mismatch: {actual}")

            tables.main()
            export_samples.main()
            if verify_tables.main() != 0:
                raise RuntimeError("independent synthetic table verification failed")
            compared, stat_failures = verify_tables.verify(
                verify_tables.load(root / "results/samples.json"),
                verify_tables.load(root / "results/tables.json"),
            )
            if stat_failures:
                raise RuntimeError(f"independent synthetic table statistics differ: {stat_failures}")

            cell = cells[0]
            paths = [schedule.cell_directory("reverse", cell) / f"key-0-fixture-{fixture_id}.json"
                     for fixture_id in schedule.pass_fixture_ids(cell, "reverse")]
            contents = [path.read_bytes() for path in paths]
            paths[0].write_bytes(contents[1])
            paths[1].write_bytes(contents[0])
            try:
                tables.session_records("reverse", cell, 0)
            except ValueError as error:
                if "session fixture identity mismatch" not in str(error):
                    raise RuntimeError(f"swapped records rejected for the wrong reason: {error}") from error
            else:
                raise RuntimeError("swapped reverse records were accepted")
            finally:
                for path, content in zip(paths, contents):
                    path.write_bytes(content)

            return {
                "status": "PASS",
                "comparison_cells": len(comparison),
                "reverse_fixture_order": [3, 2],
                "swapped_record_rejected": True,
                "scope": "self-contained synthetic records, no external archive",
                "forward_records": len(forward),
                "reverse_records": len(reverse),
                "table_statistics_compared": compared,
                "forward_receipt": forward_receipt,
                "reverse_receipt": reverse_receipt,
                "engine_execution": "mocked, real schedule.run_session, harness.bind_record and harness.validate",
                "manifest_fingerprint": "mocked, real harness.manifest_identity",
            }
        finally:
            harness.BASE = original["harness.BASE"]
            schedule.BASE = original["schedule.BASE"]
            tables.BASE = original["tables.BASE"]
            export_samples.BASE = original["export_samples.BASE"]
            export_samples.RESULTS = original["export_samples.RESULTS"]
            verify_tables.RESULTS = original["verify_tables.RESULTS"]
            harness.invoke = original["harness.invoke"]
            manifest.current_fingerprint = original["manifest.current_fingerprint"]


def r3_replay(root):
    root = root.resolve()
    schedule_document = harness.load_json(root / "results/pilot-schedule.json")
    original_base, original_tables_base = harness.BASE, tables.BASE
    original_identity, original_validate = harness.manifest_identity, harness.validate
    harness.BASE = root
    tables.BASE = root
    harness.manifest_identity = lambda: {"combined_sha256": R3_IDENTITY, "execution_identity": R3_EXECUTION}
    harness.validate = lambda result, fixture, wrong=False, check_identity=False: {"oracle": "PASS"}
    try:
        forward, forward_failures, forward_receipt = tables.load_pass("forward", schedule_document)
        reverse, reverse_failures, reverse_receipt = tables.load_pass("reverse", schedule_document)
        if forward_failures or reverse_failures:
            raise RuntimeError("retained two-pass records contain failures")
        comparison = tables.compare(tables.cell_tables(forward), tables.cell_tables(reverse))
        if len(comparison) != len(schedule_document["schedule"]):
            raise RuntimeError("two-pass cell coverage mismatch")
        cell = next(item for item in schedule_document["schedule"]
                    if item["backend"] == "pvac" and item["case"] == "S-mul" and item["profile"] == 1)
        records, failure = tables.session_records("reverse", cell, 0)
        if failure is not None:
            raise RuntimeError("reverse S-mul key 0 failed")
        actual = [record["fixture"]["fixture_id"] for record in records]
        expected = schedule.pass_fixture_ids(cell, "reverse")
        if actual != expected:
            raise RuntimeError(f"reverse fixture order mismatch: {actual} != {expected}")
        return {"status": "PASS", "forward_receipt": forward_receipt, "reverse_receipt": reverse_receipt,
                "comparison_cells": len(comparison), "reverse_fixture_order": actual,
                "reverse_s_mul_fixture_order": actual,
                "scope": "retained R3 table order and coverage, no fresh engine or oracle revalidation"}
    finally:
        harness.BASE, tables.BASE = original_base, original_tables_base
        harness.manifest_identity, harness.validate = original_identity, original_validate


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--r3", type=Path)
    args = parser.parse_args()
    if args.r3 is not None:
        summary = r3_replay(args.r3)
        output = BASE / "results/two-pass-r3-replay.json"
    else:
        summary = synthetic_control()
        output = BASE / "results/two-pass-controls.json"
    harness.write_json(output, summary)
    print(json.dumps(summary, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
