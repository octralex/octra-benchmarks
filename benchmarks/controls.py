#!/usr/bin/env python3
import argparse
import copy
import json
from pathlib import Path
import sys
import tempfile

import harness
import schedule
import tables

BASE = harness.BASE


def one(backend, case, fixture_id, threads=1, batch=1, name=None):
    output = BASE / "results" / (name or f"control-{backend}-{case}-{fixture_id}-{threads}-{batch}.json")
    args = argparse.Namespace(backend=backend, case=case, fixture_id=fixture_id, fixture=None,
                              repetitions=1, warmups=1, batch=batch, threads=threads, output=output,
                              timeout=1800, wrong_oracle=False, key_output=None)
    if harness.one(args):
        raise RuntimeError(f"control execution failed: {backend} {case}")
    return harness.load_json(output)


def rejects(function, label):
    try:
        function()
    except (ValueError, RuntimeError, TypeError, KeyError):
        return label
    raise AssertionError(f"negative control was accepted: {label}")


def synthetic_vector():
    fixture = next(f for f in schedule.load(BASE / "fixtures.json") if f["case"] == "V64" and f["fixture_id"] == 1)
    build_info = harness.platform_support.tfhe_executable_info(BASE / "tfhe-harness/target/release/pvac-comparison-tfhe")
    return fixture, {"backend": "tfhe16", "case": "V64", "logical_outputs": 64, "batch_size": 1,
                     "avx512_feature_compiled": build_info["avx512_feature_compiled"],
                     "avx512_runtime_eligible": build_info["avx512_runtime_eligible"],
                     "fixture_count": 1, "fixture_index": 0, "keygen_ms": 1.0, "key_install_ms": 1.0,
                     "encryption_ms": 1.0, "e2e_ms": 1.0, "requested_repetitions": 1, "requested_warmups": 1,
                     "eval_ms": [1.0], "decrypt_ms": [1.0], "decrypt_batch_ms": [1.0], "copy_reset_ms": [1.0],
                     "warmup_eval_ms": [1.0], "warmup_decrypt_ms": [1.0],
                     "output_bytes": [64], "batch_output_bytes": [64], "output_ciphertext_bytes": [1] * 64,
                     "input_bytes": 128, "expected_value_count": 64,
                     "process_peak_rss_bytes": 128 * 1024 * 1024,
                     "process_peak_rss_raw": 128 * 1024 * 1024 if sys.platform == "darwin" else 128 * 1024,
                     "process_peak_rss_raw_unit": "bytes" if sys.platform == "darwin" else "KiB",
                     "process_peak_rss_unit": harness.expected_rss_unit(),
                     "process_peak_rss_source": "adapter_exit",
                     "warmup_values": fixture["expected"], "values": fixture["expected"], "e2e_values": fixture["expected"]}


def table_coverage(real_record):
    original_base, original_tables_base = harness.BASE, tables.BASE
    with tempfile.TemporaryDirectory(dir=BASE / "results") as temporary:
        temporary = Path(temporary)
        try:
            harness.BASE = temporary
            tables.BASE = temporary
            (temporary / "results").mkdir()
            for name in ("fixtures.json",):
                (temporary / name).write_text((BASE / name).read_text())
            for name in ("pvac-parameters.json", "harness-manifest.json"):
                (temporary / "results" / name).write_text((BASE / "results" / name).read_text())
            cell = {"backend": "pvac", "case": "S-add", "profile": 1, "keys": 1,
                    "fixture_ids": [1], "repetitions": 1, "batch_size": 1}
            manifest = harness.manifest_identity()
            schedule_document = {"harness_sha256": manifest["combined_sha256"],
                                 "execution_identity": manifest["execution_identity"], "schedule": [cell]}
            harness.write_json(temporary / "results/pilot-schedule.json", schedule_document)
            rusage_name = Path(real_record["rusage_evidence"]).name
            (temporary / "results" / rusage_name).write_text((BASE / "results" / rusage_name).read_text())
            for pass_name in ("forward",):
                result = copy.deepcopy(real_record)
                result["requested_threads"] = 1
                result["rusage_evidence"] = f"results/{rusage_name}"
                result = harness.bind_record(result, result["fixture"], 1, real_record["execution"],
                                             temporary / "results/pilot-schedule.json")
                result["key_process_id"] = f"{pass_name}/pvac/1/S-add/key-0"
                harness.write_json(temporary / "results" / pass_name / "pvac/1/S-add/key-0-fixture-1.json", result)
                harness.write_json(temporary / "results" / f"{pass_name}-complete.json",
                                   {"status": "PASS", "key_sessions": 1, "failures": [],
                                    "harness_sha256": manifest["combined_sha256"],
                                    "execution_identity": manifest["execution_identity"],
                                    "schedule_sha256": harness.sha256_file(temporary / "results/pilot-schedule.json")})
            records, failures, _ = tables.load_pass("forward", schedule_document)
            assert len(records) == 1 and not failures
            rejects(lambda: tables.load_pass("reverse", schedule_document), "missing reverse session rejected")
            failure = {"status": "TIMEOUT", "backend": "pvac", "case": "S-add", "profile": 1,
                       "key_process_id": "reverse/pvac/1/S-add/key-0", "fixture_ids": [1],
                       "harness_identity": manifest["combined_sha256"],
                       "execution_identity": manifest["execution_identity"],
                       "fixture_sha256": manifest["fixtures_sha256"],
                       "schedule_sha256": harness.sha256_file(temporary / "results/pilot-schedule.json"),
                       "error": "controlled timeout", "session_wall_seconds": 0.0}
            harness.write_json(temporary / "results/reverse/pvac/1/S-add/key-0.failure.json", failure)
            harness.write_json(temporary / "results/reverse-complete.json",
                               {"status": "FAILURES_PRESENT", "key_sessions": 1, "failures": [failure],
                                "harness_sha256": manifest["combined_sha256"],
                                "execution_identity": manifest["execution_identity"],
                                "schedule_sha256": harness.sha256_file(temporary / "results/pilot-schedule.json")})
            reverse_records, reverse_failures, _ = tables.load_pass("reverse", schedule_document)
            assert not reverse_records and len(reverse_failures) == 1
            comparison = tables.compare(tables.cell_tables(records), tables.cell_tables(reverse_records))
            assert len(comparison) == 1 and comparison[0]["reverse_status"] == "MISSING_OR_FAILED"
        finally:
            harness.BASE, tables.BASE = original_base, original_tables_base


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--include-vector", action="store_true")
    args = parser.parse_args()
    checks = []
    records = {}
    for backend in harness.SMALL_BACKENDS:
        record = one(backend, "S-add", 1, threads=4)
        records[backend] = record
        assert record["harness_identity"] == harness.manifest_identity()["combined_sha256"]
        if backend == "pvac":
            assert record["observed_threads"] == 1 and record["requested_threads"] == 4
            if harness.sys.platform == "darwin":
                assert record["kernel"] == "gf2_conv_pmull" and record["runtime_toeplitz_id"] == 2
                assert "-mcpu=native" in record["compiler_flags"]
            else:
                assert record["kernel"] == "gf2_conv_clmul" and record["runtime_toeplitz_id"] == 1
                assert "-march=native" in record["compiler_flags"]
        elif backend.startswith("tfhe"):
            assert record["observed_threads"] == 4 and record["keygen_worker_pool"] == 4
        else:
            assert record["observed_threads"] == 4 and record["parallel_controls_limit"] == 4
            assert "binary" in record["serialization"]
        key_bytes = sum(record.get(field, 0) or 0 for field in
                        ("public_key_bytes", "relinearization_key_bytes", "rotation_key_bytes", "server_key_bytes"))
        assert record["process_peak_rss_bytes"] >= key_bytes
        assert record["execution"]["peak_rss_kib"] == record["process_peak_rss_bytes"] // 1024
        assert "sampled_rss_kib" in record["execution"]
        if record["execution"]["wall_seconds"] < 1.0:
            assert record["process_peak_rss_bytes"] > 1024 * 1024
        checks.append(f"workers-and-identity-{backend}")
        checks.append(f"exit-rss-and-key-size-{backend}")
    for backend in ("pvac", "bfv"):
        result = one(backend, "S-add", 1, batch=10)
        assert len(result["eval_ms"]) == 1 and result["batch_size"] == 10
        assert len(result["decrypt_ms"]) == 1 and len(result["output_bytes"]) == 1
        assert result["validation"]["timed_batches"] == 1 and result["validation"]["decrypted_values"] == 10
        checks.append(f"one-timing-sample-per-batch-{backend}")
    fixture, vector = synthetic_vector()
    assert harness.validate(vector, fixture)["oracle"] == "PASS"
    invalid = copy.deepcopy(vector)
    invalid["warmup_decrypt_ms"] = [1.0] * 64
    rejects(lambda: harness.validate(invalid, fixture), "V64 warmup count rejected")
    invalid = copy.deepcopy(vector)
    invalid["output_bytes"] = [64] * 64
    rejects(lambda: harness.validate(invalid, fixture), "V64 per-ciphertext/request units rejected")
    invalid = copy.deepcopy(vector)
    invalid["values"][0] = float("nan")
    invalid["backend"] = "ckks"
    rejects(lambda: harness.validate(invalid, fixture), "NaN CKKS value rejected")
    invalid = copy.deepcopy(vector)
    invalid["values"][0] = float("inf")
    invalid["backend"] = "ckks"
    rejects(lambda: harness.validate(invalid, fixture), "infinite CKKS value rejected")
    invalid = copy.deepcopy(vector)
    invalid["eval_ms"] = [-1.0]
    rejects(lambda: harness.validate(invalid, fixture), "negative timing rejected")
    invalid = copy.deepcopy(vector)
    invalid["values"][0] = fixture["expected"][0] + 0.5
    rejects(lambda: harness.validate(invalid, fixture), "fractional exact output rejected")
    invalid = copy.deepcopy(records["pvac"])
    invalid["values_lo"][0] = True
    rejects(lambda: harness.validate(invalid, invalid["fixture"], check_identity=True), "boolean field limb rejected")
    invalid = copy.deepcopy(records["pvac"])
    invalid["process_peak_rss_bytes"] = 1
    rejects(lambda: harness.validate(invalid, invalid["fixture"], check_identity=True), "impossibly small peak rejected")
    invalid = copy.deepcopy(records["pvac"])
    invalid["harness_identity"] = "stale"
    rejects(lambda: harness.validate(invalid, invalid["fixture"], check_identity=True), "stale harness identity rejected")
    invalid = copy.deepcopy(records["pvac"])
    invalid["execution_identity"] = "stale"
    rejects(lambda: harness.validate(invalid, invalid["fixture"], check_identity=True), "stale executable identity rejected")
    invalid = copy.deepcopy(records["pvac"])
    invalid["eval_ms"] = invalid["eval_ms"] * 1000
    rejects(lambda: harness.validate(invalid, invalid["fixture"]), "duplicated batch sample rejected")
    invalid_fixture = copy.deepcopy(records["pvac"]["fixture"])
    invalid_fixture["expected"][0] += 1
    rejects(lambda: harness.canonical_fixture(invalid_fixture), "tampered oracle rejected")
    path = BASE / "results/nonfinite-control.json"
    path.write_text('{"value":NaN}\n')
    rejects(lambda: harness.load_json(path), "nonfinite JSON rejected")
    rejects(lambda: harness.write_json(path, {"value": float("nan")}), "nonfinite JSON emission rejected")
    checks.extend(["synthetic-v64-schema", "nan", "infinity", "negative-timing", "fractional-exact-output", "boolean-field-limb", "impossibly-small-peak", "stale-identities", "duplicate-batch", "tampered-oracle"])
    table_coverage(records["pvac"])
    checks.append("complete-pass-coverage")
    if args.include_vector:
        result = one("tfhe16", "V64", 1)
        assert len(result["values"]) == 64 and len(result["warmup_values"]) == 64
        assert len(result["decrypt_ms"]) == 1 and len(result["output_bytes"]) == 1
        assert result["validation"]["oracle"] == "PASS"
        checks.append("actual-tfhe-v64-warmup-and-units")
    harness.write_json(BASE / "results/controls.json", {"status": "PASS", "checks": checks,
                       "worker_evidence": {backend: record["evidence_path"] if "evidence_path" in record else f"results/control-{backend}-S-add-1-4-1.json" for backend, record in records.items()}})
    print(json.dumps({"status": "PASS", "checks": checks}, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
