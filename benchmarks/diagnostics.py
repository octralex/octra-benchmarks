#!/usr/bin/env python3
import json

import harness

BASE = harness.BASE


def main():
    directory = BASE / "results/diagnostics"
    directory.mkdir(parents=True, exist_ok=True)
    output = directory / "openfhe.json"
    execution = harness.invoke([str(BASE / "build/openfhe_diagnostics"), "--output", str(output)], "",
                               directory / "openfhe", timeout=1800)
    rusage = harness.load_json(str(output) + ".rusage.json")
    execution["sampled_rss_kib"] = execution.pop("peak_rss_kib")
    execution["peak_rss_kib"] = rusage["process_peak_rss_bytes"] // 1024
    execution["process_peak_rss_bytes"] = rusage["process_peak_rss_bytes"]
    execution["peak_rss_source"] = f"adapter getrusage at exit, {rusage['process_peak_rss_unit']}"
    result = harness.load_json(output)
    for record in result["results"]:
        for operation, measurement in record["operations"].items():
            if "samples_ms" in measurement and len(measurement["samples_ms"]) != 5:
                raise ValueError(f"incomplete diagnostic: {record['backend']} {operation}")
            if operation == "Rescale" and record["backend"] != "ckks":
                if measurement.get("status") != "N/A_noop_under_selected_policy":
                    raise ValueError("non-CKKS rescale was not labelled as a no-op")
            if operation == "Rescale" and record["backend"] == "ckks":
                for field in ("input_level", "level", "input_scale", "scale"):
                    if field not in measurement:
                        raise ValueError("CKKS rescale lacks before/after state")
    harness.write_json(directory / "openfhe-receipt.json", execution)
    modulus = 1 << 64
    cases = [(modulus - 1, 2), ((1 << 63) + 5, 3), (0, modulus - 1)]
    records = []
    for index, (x, y) in enumerate(cases):
        fixture = {"case": "S-mul", "fixture_id": index, "x": [x], "y": [y],
                   "expected": [(x * y) % modulus], "bound": modulus - 1,
                   "diagnostic": "full_u64_wrap"}
        fixture_path = directory / f"tfhe64-full-width-{index}.fixture.json"
        harness.write_json(fixture_path, fixture)
        args = type("One", (), {"backend": "tfhe64", "case": "S-mul", "fixture_id": index,
                               "fixture": fixture_path, "repetitions": 1, "warmups": 1,
                               "batch": 1, "threads": 1, "output": directory / f"tfhe64-full-width-{index}.json",
                               "timeout": 1800, "wrong_oracle": False, "key_output": None})()
        if harness.one(args):
            raise RuntimeError("full-width TFHE diagnostic failed")
        record = harness.load_json(args.output)
        record["diagnostic_scope"] = "actual FheUint64 wrapping multiplication modulo 2^64, not a PVAC field127 equivalent"
        harness.write_json(args.output, record)
        records.append(str(args.output))
    identity = harness.manifest_identity()
    summary = {"status": "PASS", "harness_identity": identity["combined_sha256"],
               "execution_identity": identity["execution_identity"],
               "openfhe": str(output), "tfhe64_full_u64": records,
               "excluded_from_primary_tables": True,
               "not_run": "depth-12 screenshot reproduction, legacy encrypted-coefficient cubic, optional PVAC full-field and Boolean gate diagnostics"}
    harness.write_json(directory / "summary.json", summary)
    print(json.dumps(summary, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
