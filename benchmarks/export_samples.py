#!/usr/bin/env python3
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
RESULTS = BASE / "results"
FIELDS = ("eval_ms", "decrypt_ms", "output_bytes")


def main():
    schedule = json.loads((RESULTS / "pilot-schedule.json").read_text())["schedule"]
    passes = {}
    for name in ("forward", "reverse"):
        sessions = []
        for cell in schedule:
            fixture_ids = list(cell["fixture_ids"])
            if name == "reverse":
                fixture_ids.reverse()
            for key in range(cell["keys"]):
                import schedule as schedule_paths
                directory = schedule_paths.cell_directory(name, cell)
                lines = (directory / f"key-{key}.session.jsonl").read_text().splitlines()
                if len(lines) != len(fixture_ids):
                    raise RuntimeError(f"incomplete session: {directory} key {key}")
                peak = json.loads((directory / f"key-{key}.rusage.json").read_text())["process_peak_rss_bytes"]
                fixtures = []
                for fixture_id, line in zip(fixture_ids, lines):
                    record = json.loads(line)
                    setup = None
                    if record.get("keygen_ms") is not None:
                        setup = record["keygen_ms"] + (record.get("key_install_ms") or 0.0)
                    entry = {"fixture_id": fixture_id, "batch_size": record["batch_size"],
                             "encryption_ms": record["encryption_ms"], "e2e_ms": record["e2e_ms"],
                             "setup_ms": setup, "input_bytes": record["input_bytes"],
                             "physical_input_ciphertexts": record["physical_input_ciphertexts"]}
                    for field in FIELDS:
                        entry[field] = record[field]
                    for field in ("public_key_bytes", "relinearization_key_bytes", "rotation_key_bytes",
                                  "server_key_bytes", "ring_dimension"):
                        if record.get(field) is not None:
                            entry[field] = record[field]
                    fixtures.append(entry)
                lattice_wide = schedule_paths.lattice_wide(cell["backend"], cell["case"])
                sessions.append({"backend": cell["backend"], "case": cell["case"], "profile": cell["profile"],
                                 "representation": cell.get("representation") if lattice_wide else None,
                                 "key_switch_requested": cell.get("key_switch") if lattice_wide else None,
                                 "key": key, "process_peak_rss_bytes": peak, "fixtures": fixtures})
        passes[name] = sessions
    document = {"schema": 1, "harness_sha256": json.loads((RESULTS / "pilot-schedule.json").read_text())["harness_sha256"],
                "units": "milliseconds and bytes, peak memory is per key session process", "passes": passes}
    (RESULTS / "samples.json").write_text(json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
    print(json.dumps({"sessions": {name: len(items) for name, items in passes.items()}}, allow_nan=False))


if __name__ == "__main__":
    main()
