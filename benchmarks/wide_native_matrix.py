#!/usr/bin/env python3
import json
from pathlib import Path
import subprocess

import harness

BASE = harness.BASE
P = (1 << 127) - 1


def main():
    directory = BASE / "results/native-matrix"
    directory.mkdir(parents=True, exist_ok=True)
    summary_path = directory / "summary.json"
    if summary_path.exists():
        summary = harness.load_json(summary_path)
        if summary.get("harness_identity") == harness.manifest_identity()["combined_sha256"]:
            print(json.dumps({"status": summary["status"], "passed": summary["passed"], "rejected": summary["rejected"],
                              "summary": str(summary_path), "reused": True}, indent=2))
            return
    fixtures = harness.load_json(BASE / "fixtures.json")
    observations = []
    cases = [
        ("I63-mul", 2, str((1 << 63) - 1), str((1 << 63) - 1)),
        ("F127-add", 1, "1", str(P - 1)),
        ("F127-mul", 2, str(P - 1), str(P - 1)),
        ("D25-d1", 2, ",".join([str((1 << 25) - 1)] * 5), ""),
        ("D25-d2", 2, ",".join([str((1 << 25) - 1)] * 5), ""),
        ("D25-d4", 2, ",".join([str((1 << 25) - 1)] * 5), ""),
    ]
    for case, fixture_id, x, y in cases:
        fixture = next(item for item in fixtures if item["case"] == case and item["fixture_id"] == fixture_id)
        for backend in ("pvac", "bfv", "bgv", "tfhe-wide"):
            if backend == "tfhe-wide" and not (case.startswith("D25") or case == "F127-add"):
                continue
            representations = ("native",) if backend in ("pvac", "tfhe-wide") else ("coef-binary", "coef-radix", "crt30")
            for representation in representations:
                key_switches = ("HYBRID", "BV") if backend == "bfv" and case == "D25-d4" else ("HYBRID",)
                for key_switch in key_switches:
                    stem = f"{backend}-{case}-{representation}-{key_switch}"
                    output = directory / f"{stem}.json"
                    if backend == "pvac":
                        command = [str(BASE / "build/pvac_wide")]
                    elif backend == "tfhe-wide":
                        command = [str(BASE / "tfhe-harness/target/release/pvac-comparison-tfhe"), "--wide"]
                    else:
                        command = [str(BASE / "build/openfhe_wide"), "--backend", backend]
                    command += ["--case", case, "--output", str(output), "--repetitions", "1",
                                "--warmups", "1", "--batch", "1", "--threads", "1"]
                    if backend in ("bfv", "bgv"):
                        command += ["--representation", representation, "--key-switch", key_switch]
                    completed = subprocess.run(command, input=f"{x}\n{y}\n", text=True, capture_output=True, timeout=1800)
                    record = {"backend": backend, "case": case, "representation": representation,
                              "key_switch": key_switch, "returncode": completed.returncode,
                              "stderr": completed.stderr[-2000:]}
                    if completed.returncode == 0:
                        result = harness.load_json(output)
                        result.update(harness.load_json(str(output) + ".rusage.json"))
                        harness.validate(result, fixture)
                        record["status"] = "PASS"
                        record["evidence"] = str(output.relative_to(BASE))
                    else:
                        record["status"] = "REJECTED_CANDIDATE"
                    observations.append(record)
                    print(json.dumps(record, allow_nan=False), flush=True)
    required = []
    for case, _, _, _ in cases:
        for backend in ("pvac", "bfv", "bgv", "tfhe-wide"):
            if backend == "tfhe-wide" and not (case.startswith("D25") or case == "F127-add"):
                continue
            group = [record for record in observations if record["backend"] == backend and record["case"] == case]
            if not group or not any(record["status"] == "PASS" for record in group):
                required.append({"backend": backend, "case": case})
    if required:
        raise RuntimeError(f"required native representation coverage failed: {required}")
    identity = harness.manifest_identity()
    summary = {"status": "PASS_WITH_CANDIDATE_REJECTIONS", "observations": observations,
               "harness_identity": identity["combined_sha256"], "execution_identity": identity["execution_identity"],
               "passed": sum(record["status"] == "PASS" for record in observations),
               "rejected": sum(record["status"] != "PASS" for record in observations),
               "required_coverage": "every backend and case has an admitted passing representation, every candidate outcome is retained",
               "scope": "native boundary correctness only, no timing admitted"}
    harness.write_json(directory / "summary.json", summary)
    print(json.dumps({"status": summary["status"], "passed": summary["passed"], "rejected": summary["rejected"],
                      "summary": str(directory / "summary.json")}, indent=2))


if __name__ == "__main__":
    main()
