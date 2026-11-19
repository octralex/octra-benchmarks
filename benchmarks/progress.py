#!/usr/bin/env python3
import datetime
import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent


def main():
    stage, status = sys.argv[1:]
    manifest = json.loads((BASE / "results/harness-manifest.json").read_text())
    record = {"stage": stage, "status": status,
              "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "harness_identity": manifest["combined_sha256"]}
    (BASE / "state").mkdir(exist_ok=True)
    with (BASE / "state/progress.jsonl").open("a") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
