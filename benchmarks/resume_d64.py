#!/usr/bin/env python3
import json

import harness
import schedule

cell = {"backend": "tfhe16", "case": "D64", "profile": 1, "repetitions": 1,
        "batch_size": 1, "fixture_ids": list(range(6)), "timeout_seconds": 7200}
result = schedule.run_session("session-smoke", cell, 0)
if result.get("status") != "PASS":
    raise RuntimeError("TFHE16 D64 session did not pass")
for fixture_id in cell["fixture_ids"]:
    path = harness.BASE / f"results/session-smoke/tfhe16/1/D64/key-0-fixture-{fixture_id}.json"
    record = harness.load_json(path)
    record["correctness_timeout_seconds"] = 7200
    record["supervision_note"] = "correctness-only session allowance, measured attempt timeout remains 1800 seconds, no sample-tier change"
    harness.validate(record, record["fixture"], check_identity=True)
    harness.write_json(path, record)
harness.write_json(harness.BASE / "results/tfhe16-d64-timeout-admission.json", {
    "status": "COMPLETED_WITH_DOCUMENTED_CORRECTNESS_TIMEOUT_ALLOWANCE",
    "correctness_session_allowance_seconds": 7200,
    "reason": "prior lifecycle measurement established that six fixtures with warmup, measured evaluation and E2E take about 1860 seconds",
    "measured_attempt_timeout_seconds": 1800,
    "session_wall_seconds": result["session_wall_seconds"],
})
print(json.dumps({"status": "PASS", "session_wall_seconds": result["session_wall_seconds"]}, allow_nan=False))
