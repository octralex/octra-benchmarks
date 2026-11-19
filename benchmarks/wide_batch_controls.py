#!/usr/bin/env python3
import argparse
import json

import harness

BASE = harness.BASE


def main():
    observations = []
    for backend in ("pvac", "bfv", "bgv", "tfhe-wide"):
        batch = 4 if backend != "tfhe-wide" else 2
        output = BASE / "results/wide-batch" / f"{backend}.json"
        status = harness.one(argparse.Namespace(backend=backend, case="F127-add", fixture_id=1, fixture=None,
                                                repetitions=1, warmups=1, batch=batch, threads=1, output=output,
                                                timeout=1800, wrong_oracle=False, key_output=None,
                                                representation="coef-binary", key_switch="AUTO"))
        if status:
            raise RuntimeError(f"wide addition batch failed: {backend}")
        result = harness.load_json(output)
        assert result["batch_size"] == batch
        assert result["expected_value_count"] == batch
        assert len(result["values_decimal"]) == batch
        assert len(result["output_ciphertext_bytes"]) == batch
        assert result["batch_output_bytes"] == [sum(result["output_ciphertext_bytes"])]
        assert abs(result["output_bytes"][0] * batch - result["batch_output_bytes"][0]) < 1e-6
        assert result["decrypt_batch_ms"] == [result["decrypt_ms"][0] * batch]
        observations.append({"backend": backend, "batch": batch, "status": "PASS",
                             "evidence": str(output.relative_to(BASE))})
    report = {"status": "PASS", "observations": observations,
              "scope": "native batch counts and units, no timing admitted"}
    harness.write_json(BASE / "results/wide-batch-controls.json", report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
