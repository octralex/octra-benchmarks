#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path

import harness

BASE = harness.BASE
BACKENDS = harness.BACKENDS
CASES = harness.CASES


def load(path):
    return harness.load_json(path)


def digest(path):
    return harness.sha256_file(path)


def run_one(backend, case, fixture_id, threads, repetitions, batch, output, timeout=1800, key_output=None,
            representation="coef-binary", key_switch="AUTO"):
    args = argparse.Namespace(backend=backend, case=case, fixture_id=fixture_id, fixture=None,
                              repetitions=repetitions, warmups=1, batch=batch, threads=threads,
                              output=Path(output), timeout=timeout, wrong_oracle=False, key_output=key_output,
                              representation=representation, key_switch=key_switch)
    if harness.one(args):
        raise RuntimeError(f"failed cell: {backend} {case} profile={threads} fixture={fixture_id}")
    return load(output)


def cells():
    from fixtures import SMALL_CASES, WIDE_CASES
    for case in SMALL_CASES:
        for profile in (1, 4):
            for backend in harness.SMALL_BACKENDS:
                if backend == "tfhe64" and case not in ("S-add", "S-mul"):
                    continue
                yield backend, case, profile
    for case in WIDE_CASES:
        for profile in (1, 4):
            for backend in harness.WIDE_BACKENDS:
                yield backend, case, profile


def lattice_wide(backend, case):
    from fixtures import WIDE_CASES
    return backend in ("bfv", "bgv") and case in WIDE_CASES


def cell_variant(cell):
    if not lattice_wide(cell["backend"], cell["case"]):
        return ""
    return f"{cell.get('representation', 'coef-binary')}-{cell.get('key_switch', 'AUTO')}"


def cell_directory(pass_name, cell):
    directory = harness.BASE / "results" / pass_name / cell["backend"] / str(cell["profile"]) / cell["case"]
    variant = cell_variant(cell)
    return directory / variant if variant else directory


def key_process_id(pass_name, cell, key):
    suffix = cell_variant(cell)
    base = f"{pass_name}/{cell['backend']}/{cell['profile']}/{cell['case']}/key-{key}"
    return f"{base}/{suffix}" if suffix else base


def session_failure(pass_name, cell, key, error, log_stem):
    execution_path = log_stem.with_suffix(".execution.json")
    execution = load(execution_path) if execution_path.exists() else None
    if execution and execution.get("timed_out"):
        status = "TIMEOUT"
    elif execution and execution.get("memory_exceeded"):
        status = "MEMORY_LIMIT"
    else:
        status = "ERROR"
    manifest = harness.manifest_identity()
    return {"schema": harness.SCHEMA, "status": status, "backend": cell["backend"], "case": cell["case"],
            "profile": cell["profile"], "key_process_id": key_process_id(pass_name, cell, key),
            "fixture_ids": cell["fixture_ids"], "error": str(error), "execution": execution,
            "harness_identity": manifest["combined_sha256"], "execution_identity": manifest["execution_identity"],
            "fixture_sha256": manifest["fixtures_sha256"], "schedule_sha256": digest(BASE / "results/pilot-schedule.json"),
            "session_wall_seconds": execution["wall_seconds"] if execution else 0.0}


def run_session(pass_name, cell, key):
    backend, case, profile = cell["backend"], cell["case"], cell["profile"]
    fixture_ids = cell["fixture_ids"]
    fixture_file = cell.get("fixture_file", "fixtures.json")
    fixtures = {f["fixture_id"]: f for f in load(BASE / fixture_file) if f["case"] == case}
    directory = cell_directory(pass_name, cell)
    outputs = [directory / f"key-{key}-fixture-{fixture_id}.json" for fixture_id in fixture_ids]
    expected_key_id = key_process_id(pass_name, cell, key)
    if all(path.exists() for path in outputs):
        records = [load(path) for path in outputs]
        for index, (record, fixture_id) in enumerate(zip(records, fixture_ids)):
            if record["fixture"].get("fixture_id") != fixture_id:
                raise RuntimeError("retained session fixture identity mismatch")
            if record.get("status") != "PASS" or record.get("key_process_id") != expected_key_id:
                raise RuntimeError(f"invalid retained session record: {record.get('evidence_path', 'unknown')}")
            if record.get("fixture_index") != index:
                raise RuntimeError("retained session fixture order mismatch")
            harness.validate(record, fixtures[fixture_id], check_identity=True)
        if len({record["key_process_id"] for record in records}) != 1:
            raise RuntimeError("mixed key sessions in retained records")
        return records[0]
    directory.mkdir(parents=True, exist_ok=True)
    raw_path = directory / f"key-{key}.session.jsonl"
    log_stem = directory / f"key-{key}.session"
    argv = harness.command(backend, case, cell.get("representation", "coef-binary"), cell.get("key_switch", "AUTO")) + [
                                      "--case", case, "--output", str(raw_path) + ".tmp",
                                      "--repetitions", str(cell["repetitions"]), "--warmups", "1",
                                      "--batch", str(cell["batch_size"]), "--fixture-count", str(len(fixture_ids)),
                                      "--threads", str(profile)]
    stdin = "".join(",".join(map(str, fixtures[fixture_id][operand])) + "\n"
                    for fixture_id in fixture_ids for operand in ("x", "y"))
    schedule_path = BASE / "results/pilot-schedule.json" if pass_name in ("forward", "reverse") else None
    try:
        execution = harness.invoke(argv, stdin, log_stem, cell.get("timeout_seconds", 1800))
        rusage_path = Path(str(raw_path) + ".tmp.rusage.json")
        rusage = harness.load_json(rusage_path)
        final_rusage_path = directory / f"key-{key}.rusage.json"
        rusage_path.replace(final_rusage_path)
        lines = Path(str(raw_path) + ".tmp").read_text().splitlines()
        if len(lines) != len(fixture_ids):
            raise RuntimeError(f"incomplete key session: {backend} {case} key={key}")
        session_parameters = None
        parameters_path = directory / f"key-{key}.parameters.json"
        records = []
        for index, line in enumerate(lines):
            def reject_constant(value):
                raise ValueError(f"nonfinite JSON constant in session: {value}")
            result = json.loads(line, parse_constant=reject_constant)
            if result["fixture_index"] != index or result["fixture_count"] != len(fixture_ids):
                raise RuntimeError("session fixture linkage mismatch")
            if backend in ("bfv", "bgv", "ckks"):
                if index == 0:
                    session_parameters = result["parameters_json"]
                    harness.write_json(parameters_path, {"parameters_json": session_parameters})
                result["parameters_json"] = None
                result["parameters_ref"] = str(parameters_path.relative_to(BASE))
            result["requested_repetitions"] = cell["repetitions"]
            result["requested_warmups"] = 1
            result.update(rusage)
            result["rusage_evidence"] = str(final_rusage_path.relative_to(BASE))
            result["validation"] = harness.validate(result, fixtures[fixture_ids[index]])
            result = harness.bind_record(result, fixtures[fixture_ids[index]], profile, execution, schedule_path)
            result["status"] = "PASS"
            result["key_process_id"] = expected_key_id
            result["session_evidence"] = str(raw_path.relative_to(BASE))
            result["session_wall_seconds"] = execution["wall_seconds"]
            result["evidence_path"] = str(outputs[index].relative_to(BASE))
            harness.write_json(outputs[index], result)
            records.append(result)
        Path(str(raw_path) + ".tmp").replace(raw_path)
        return records[0]
    except Exception as error:
        if pass_name not in ("forward", "reverse"):
            raise
        failure = session_failure(pass_name, cell, key, error, log_stem)
        harness.write_json(directory / f"key-{key}.failure.json", failure)
        return failure


def pilot_variants(backend, case, profile):
    if lattice_wide(backend, case):
        import representations
        selected = representations.selected_cells(backend, case, profile)
    else:
        selected = [{"representation": "coef-binary", "key_switch": "AUTO", "selection_roles": ["native"]}]
    return [dict(backend=backend, case=case, profile=profile, **variant) for variant in selected]


def pilot_output(root, cell):
    directory = BASE / "results" / root / cell["backend"] / str(cell["profile"])
    if lattice_wide(cell["backend"], cell["case"]):
        return directory / cell["case"] / f"{cell_variant(cell)}.json"
    return directory / f"{cell['case']}.json"


def pilot(args):
    import representations
    representations.require_selection()
    fixtures = load(BASE / "fixtures.json")
    for backend, case, profile in cells():
        if args.backends and backend not in args.backends:
            continue
        for cell in pilot_variants(backend, case, profile):
            output = pilot_output("pilot", cell)
            if output.exists() and not args.force:
                result = load(output)
                fixture = next(f for f in fixtures if f["case"] == case and f["fixture_id"] == 3)
                harness.validate(result, fixture, check_identity=True)
                continue
            observations = harness.wait_for_quiet(args.gate_timeout, args.load_threshold)
            result = run_one(backend, case, 3, profile, 1, 1, output, timeout=1800,
                             representation=cell["representation"], key_switch=cell["key_switch"])
            result["load_gate"] = observations[-1]
            harness.write_json(output, result)
            print(json.dumps({"backend": backend, "case": case, "profile": profile,
                              "representation": cell["representation"], "key_switch": cell["key_switch"],
                              "pilot_eval_ms": result["eval_ms"][0], "status": result["validation"]["oracle"]}), flush=True)


def micro(args):
    for backend, case, profile in cells():
        for cell in pilot_variants(backend, case, profile):
            path = pilot_output("pilot", cell)
            result = load(path)
            if result["eval_ms"][0] >= 0.1:
                continue
            if backend.startswith("tfhe"):
                raise RuntimeError("a TFHE operation requires an explicitly implemented micro-batch path")
            output = pilot_output("pilot-micro", cell)
            if output.exists() and not args.force:
                harness.validate(load(output), result["fixture"], check_identity=True)
                continue
            harness.wait_for_quiet(args.gate_timeout, args.load_threshold)
            result = run_one(backend, case, 3, profile, 1, 1000, output, timeout=1800,
                             representation=cell["representation"], key_switch=cell["key_switch"])
            print(json.dumps({"backend": backend, "case": case, "profile": profile,
                              "batch": result["batch_size"], "per_call_ms": result["eval_ms"][0]}), flush=True)


def sample_tier(seconds):
    if seconds < 2:
        return 3, 6, 5, "under_2s"
    if seconds <= 60:
        return 3, 2, 1, "2s_to_60s"
    if seconds <= 600:
        return 3, 1, 1, "60s_to_10min"
    return 1, 1, 1, "over_10min_single_attempt"


def timed_fixture_ids(case, count):
    from fixtures import WIDE_CASES
    if case not in WIDE_CASES:
        return list(range(count))
    if case.startswith("F127"):
        preferred = [2, 6, 7, 0, 1, 3, 4, 5]
    else:
        preferred = [2, 4, 5, 0, 1, 3]
    if len(preferred) < count:
        raise RuntimeError(f"wide fixture coverage cannot satisfy tier count {count}: {case}")
    return preferred[:count]


def pilot_cell(cell):
    path = pilot_output("pilot", cell)
    result = load(path)
    seconds = result["eval_ms"][0] / 1000.0
    keys, fixture_count, repetitions, tier = sample_tier(seconds)
    batch = 1
    if seconds < 0.0001:
        micro_result = load(pilot_output("pilot-micro", cell))
        if micro_result["batch_size"] != 1000:
            raise RuntimeError("micro-batch evidence missing")
        batch = 1000
    return {**cell, "tier": tier, "pilot_eval_ms": result["eval_ms"][0], "keys": keys,
            "fixture_ids": timed_fixture_ids(cell["case"], fixture_count), "repetitions": repetitions,
            "batch_size": batch, "timeout_seconds": 1800, "pilot_evidence": str(path)}


def session_pilot(args):
    for backend, case, profile in cells():
        for variant in pilot_variants(backend, case, profile):
            cell = pilot_cell(variant)
            output = cell_directory("session-pilot", cell) / f"key-0-fixture-{cell['fixture_ids'][0]}.json"
            if output.exists() and not args.force:
                result = load(output)
                harness.validate(result, result["fixture"], check_identity=True)
                continue
            harness.wait_for_quiet(args.gate_timeout, args.load_threshold)
            result = run_session("session-pilot", cell, 0)
            print(json.dumps({"backend": backend, "case": case, "profile": profile,
                              "session_wall_seconds": result["session_wall_seconds"]}), flush=True)


def validate_selected_sessions(identity):
    selected = selected_correctness_cells()
    sessions = load(BASE / "results/session-smoke-summary.json")
    if sessions.get("harness_identity") != identity["combined_sha256"] or sessions.get("execution_identity") != identity["execution_identity"]:
        raise RuntimeError("stale same-key session summary")
    selected_sessions = sessions.get("selected_sessions", [])
    expected_identities = {(cell["backend"], cell["case"], cell["profile"], cell["representation"], cell["key_switch"],
                            tuple(cell["fixture_ids"])) for cell in selected}
    actual_identities = {(cell["backend"], cell["case"], cell["profile"], cell["representation"], cell["key_switch"],
                          tuple(cell["fixture_ids"])) for cell in selected_sessions}
    if len(selected_sessions) != len(selected) or actual_identities != expected_identities:
        raise RuntimeError("selected same-key session identities or fixture coverage differ from the selected set")
    fixture_data = load(BASE / "fixtures.json")
    expected = {}
    for cell in selected:
        expected_key = key_process_id("session-smoke-selected", cell, 0)
        for index, fixture_id in enumerate(cell["fixture_ids"]):
            path = cell_directory("session-smoke-selected", cell) / f"key-0-fixture-{fixture_id}.json"
            fixture = next(item for item in fixture_data if item["case"] == cell["case"] and item["fixture_id"] == fixture_id)
            expected[str(path.resolve())] = (cell, index, fixture, expected_key)
    selected_records = sessions.get("selected_records", [])
    actual_paths = [str(Path(relative).resolve()) for relative in selected_records]
    if len(actual_paths) != len(set(actual_paths)) or set(actual_paths) != set(expected):
        raise RuntimeError("selected record paths are duplicated, missing or outside the exact expected record map")
    session_parameters = {}
    for relative in actual_paths:
        cell, index, fixture, expected_key = expected[relative]
        result = load(relative)
        if result.get("status") != "PASS":
            raise RuntimeError(f"missing or rejected selected correctness record: {relative}")
        expected_technique = cell["key_switch"]
        if expected_technique == "AUTO":
            expected_technique = "BV" if cell["backend"] == "bfv" and cell["case"].startswith("D25") else "HYBRID"
        expected_fields = {
            "backend": cell["backend"],
            "case": cell["case"],
            "profile": cell["profile"],
            "representation": cell["representation"],
            "key_switch_requested": cell["key_switch"],
            "key_switch_technique": expected_technique,
            "key_process_id": expected_key,
            "fixture": fixture,
            "fixture_index": index,
            "fixture_count": len(cell["fixture_ids"]),
        }
        for field, expected_value in expected_fields.items():
            if result.get(field) != expected_value:
                raise RuntimeError(f"selected record {field} mismatch: {relative}")
        harness.validate(result, fixture, check_identity=True)
        session_parameters.setdefault(expected_key, set()).add(result["parameter_sha256"])
    if any(len(parameters) != 1 for parameters in session_parameters.values()):
        raise RuntimeError("selected session mixes parameter or key identities")
    return selected, sessions, selected_records


def freeze(args):
    expected_records = []
    admitted = {(backend, case) for backend, case, profile in cells() if profile == 1}
    fixtures = load(BASE / "fixtures.json")
    required_records = sum(1 for fixture in fixtures for backend in BACKENDS if (backend, fixture["case"]) in admitted)
    for fixture in fixtures:
        for backend in BACKENDS:
            if (backend, fixture["case"]) not in admitted:
                continue
            path = BASE / "results/smoke" / backend / f"{fixture['case']}-{fixture['fixture_id']}.json"
            result = load(path)
            if result.get("status") != "PASS":
                raise RuntimeError(f"missing or rejected correctness record: {path}")
            harness.validate(result, fixture, check_identity=True)
            expected_records.append(str(path))
    if len(expected_records) != required_records:
        raise RuntimeError(f"complete {required_records}-record correctness smoke is required before freezing")
    identity = harness.manifest_identity()
    selected, sessions, selected_records = validate_selected_sessions(identity)
    required_sessions = len(admitted) + len(selected)
    if sessions.get("status") != "PASS" or len(sessions["sessions"]) != required_sessions:
        raise RuntimeError(f"all {required_sessions} baseline and selected same-key sessions are required before freezing")
    expected_records.extend(selected_records)
    required_records += len(selected_records)
    if len(expected_records) != required_records:
        raise RuntimeError(f"complete {required_records}-record baseline and selected correctness coverage is required before freezing")
    for evidence in ("results/diagnostics/summary.json", "results/parameter-security.json"):
        document = load(BASE / evidence)
        if document.get("status") != "PASS":
            raise RuntimeError(f"required evidence failed: {evidence}")
        if document.get("harness_identity") != identity["combined_sha256"] or document.get("execution_identity") != identity["execution_identity"]:
            raise RuntimeError(f"stale evidence identity: {evidence}")
    schedule = []
    for backend, case, profile in cells():
        for variant in pilot_variants(backend, case, profile):
            cell = pilot_cell(variant)
            session_path = cell_directory("session-pilot", cell) / f"key-0-fixture-{cell['fixture_ids'][0]}.json"
            session = load(session_path)
            cell["estimated_wall_seconds"] = cell["keys"] * session["session_wall_seconds"]
            cell["session_pilot_evidence"] = str(session_path)
            schedule.append(cell)
    profile_estimates = {str(profile): sum(cell["estimated_wall_seconds"] for cell in schedule
                                           if cell["profile"] == profile) for profile in (1, 4)}
    for profile, seconds in profile_estimates.items():
        if seconds > 12 * 3600:
            raise RuntimeError(f"pilot schedule exceeds twelve-hour budget for profile {profile}: {seconds}")
    import manifest
    fingerprint = manifest.current_fingerprint()
    document = {
        "status": "frozen",
        "harness_sha256": fingerprint,
        "execution_identity": harness.manifest_identity()["execution_identity"],
        "representation_selection_sha256": digest(BASE / "results/representation-selection.json"),
        "profile_estimated_seconds": profile_estimates,
        "pilot_power_policy": "macOS requires AC, all venues require quiet load, safe thermal state and zero swap, Linux records governor and boost",
        "venue": f"{harness.sys.platform}, recorded host and CPU topology, pinned taskset on Linux and unpinned on macOS",
        "shared_venue_caveat": "dedicated idle host required for admitted timing, no hardware or security-equivalence claim",
        "sampling_rule": {"under_2s": [3, 6, 5], "2s_to_60s": [3, 2, 1],
                          "60s_to_10min": [3, 1, 1], "over_10min": "one attempt, n=1 or timeout at 1800s"},
        "warmups": 1,
        "fixture_policy": f"all {len(fixtures)} fixtures validated in smoke, timed fixture counts selected only by pilot tier",
        "per_process_memory_cap": "8 GiB sampled RSS supervision, adapter exit RSS is authoritative, no unsupported address-space cap",
        "profile_budget_seconds": 12 * 3600,
        "forward_reverse_required": True,
        "schedule": schedule,
        "pilot_sha256": {str(p.relative_to(BASE)): digest(p) for p in sorted((BASE / "results/pilot").glob("*/*/*.json"))},
        "pilot_variant_sha256": {str(p.relative_to(BASE)): digest(p) for p in sorted((BASE / "results/pilot").glob("*/*/*/*.json"))},
        "micro_sha256": {str(p.relative_to(BASE)): digest(p) for p in sorted((BASE / "results/pilot-micro").glob("*/*/*.json"))},
        "micro_variant_sha256": {str(p.relative_to(BASE)): digest(p) for p in sorted((BASE / "results/pilot-micro").glob("*/*/*/*.json"))},
        "session_pilot_sha256": {str(p.relative_to(BASE)): digest(p) for p in sorted((BASE / "results/session-pilot").glob("*/*/*/*.json"))},
        "session_pilot_variant_sha256": {str(p.relative_to(BASE)): digest(p) for p in sorted((BASE / "results/session-pilot").glob("*/*/*/*/*.json"))},
    }
    path = BASE / "results/pilot-schedule.json"
    harness.write_json(path, document)
    print(json.dumps({"schedule": str(path), "sha256": digest(path), "cells": len(schedule),
                      "estimated_one_pass_hours": sum(x["estimated_wall_seconds"] for x in schedule) / 3600,
                      "estimated_two_pass_hours": 2 * sum(x["estimated_wall_seconds"] for x in schedule) / 3600}, indent=2, allow_nan=False))


def frozen_identity():
    stored = harness.manifest_identity()
    import manifest
    if manifest.current_fingerprint() != stored["combined_sha256"]:
        raise RuntimeError("harness or executable changed after the schedule was frozen")
    return stored


def reject_constant(value):
    raise ValueError(f"nonfinite JSON constant in schedule: {value}")


def frozen_schedule(schedule_path):
    stored = frozen_identity()
    raw = Path(schedule_path).read_bytes()
    document = json.loads(raw, parse_constant=reject_constant)
    if document.get("status") != "frozen":
        raise RuntimeError("schedule is not frozen, run schedule.py freeze first")
    if (document.get("harness_sha256") != stored["combined_sha256"] or
            document.get("execution_identity") != stored["execution_identity"]):
        raise RuntimeError("schedule was frozen for a different harness or executable")
    listed = [(cell.get("backend"), cell.get("case"), cell.get("profile"),
               cell.get("representation", "coef-binary"), cell.get("key_switch", "AUTO"))
              for cell in document.get("schedule", [])]
    covered = {(backend, case, profile) for backend, case, profile, _, _ in listed}
    if len(listed) != len(set(listed)) or covered != set(cells()):
        raise RuntimeError("schedule cells differ from the workload matrix")
    import representations
    selection = representations.require_selection()
    if document.get("representation_selection_sha256") != digest(representations.SELECTION):
        raise RuntimeError("schedule is not bound to the current representation selection")
    fixtures = load(BASE / "fixtures.json")
    for cell in document["schedule"]:
        fixture_ids = cell.get("fixture_ids")
        valid_ids = {fixture["fixture_id"] for fixture in fixtures if fixture["case"] == cell["case"]}
        counts = [cell.get("keys"), cell.get("repetitions"), cell.get("batch_size"), cell.get("timeout_seconds")]
        if (any(type(value) is not int or value < 1 for value in counts) or type(fixture_ids) is not list or
                not fixture_ids or len(fixture_ids) != len(set(fixture_ids)) or
                any(type(value) is not int or value not in valid_ids for value in fixture_ids)):
            raise RuntimeError(f"malformed schedule cell: {cell.get('backend')} {cell.get('case')} {cell.get('profile')}")
        if cell.get("representation", "coef-binary") not in ("coef-binary", "coef-radix", "crt30"):
            raise RuntimeError("unknown representation in frozen schedule")
        if lattice_wide(cell["backend"], cell["case"]):
            selected = representations.selected_cells(cell["backend"], cell["case"], cell["profile"])
            identity = {"representation": cell["representation"], "key_switch": cell["key_switch"]}
            if not any(item["representation"] == identity["representation"] and item["key_switch"] == identity["key_switch"]
                       for item in selected):
                raise RuntimeError("schedule contains an unselected representation or key-switch candidate")
    for backend, case, profile in cells():
        if not lattice_wide(backend, case):
            continue
        expected = {(item["representation"], item["key_switch"])
                    for item in representations.selected_cells(backend, case, profile)}
        actual = {(cell["representation"], cell["key_switch"])
                  for cell in document["schedule"]
                  if cell["backend"] == backend and cell["case"] == case and cell["profile"] == profile}
        if actual != expected:
            raise RuntimeError(f"scheduled variant set differs from selected set: {backend} {case} profile {profile}")
    budget = document.get("profile_budget_seconds")
    if type(budget) not in (int, float) or budget <= 0 or not harness.math.isfinite(budget):
        raise RuntimeError("schedule has no valid finite profile budget")
    return stored, document, hashlib.sha256(raw).hexdigest()


def pass_fixture_ids(cell, pass_name):
    fixture_ids = list(cell["fixture_ids"])
    return list(reversed(fixture_ids)) if pass_name == "reverse" else fixture_ids


def interleaved_tasks(schedule, pass_name):
    tasks = []
    for case in CASES:
        for profile in (1, 4):
            group = [cell for cell in schedule["schedule"] if cell["case"] == case and cell["profile"] == profile]
            for key in range(max(cell["keys"] for cell in group)):
                for cell in group:
                    if key >= cell["keys"]:
                        continue
                    selected = dict(cell)
                    selected["fixture_ids"] = pass_fixture_ids(cell, pass_name)
                    tasks.append((selected, key))
    if pass_name == "reverse":
        tasks.reverse()
    return tasks


def long_run(args):
    schedule_path = BASE / "results/pilot-schedule.json"
    stored, schedule, schedule_sha256 = frozen_schedule(schedule_path)
    tasks = interleaved_tasks(schedule, args.pass_name)
    profile_execution_seconds = {1: 0.0, 4: 0.0}
    failures = []
    for index, (cell, key) in enumerate(tasks):
        harness.wait_for_quiet(args.gate_timeout, args.load_threshold)
        profile = cell["profile"]
        if profile_execution_seconds[profile] > schedule["profile_budget_seconds"]:
            raise RuntimeError(f"execution budget exceeded for profile {profile}")
        result = run_session(args.pass_name, cell, key)
        profile_execution_seconds[profile] += result["session_wall_seconds"]
        if result.get("status") != "PASS":
            failures.append({"backend": cell["backend"], "case": cell["case"], "profile": profile,
                             "key": key, "status": result["status"], "error": result["error"]})
        progress = {"pass": args.pass_name, "completed_key_sessions": index + 1, "total_key_sessions": len(tasks),
                    "manifest_sha256": stored["combined_sha256"],
                    "execution_identity": stored["execution_identity"],
                    "schedule_sha256": schedule_sha256, "failures": failures,
                    "profile_execution_seconds": profile_execution_seconds}
        harness.write_json(BASE / "results" / f"{args.pass_name}-progress.json", progress)
        print(json.dumps(progress, allow_nan=False), flush=True)
    import manifest
    if manifest.current_fingerprint() != stored["combined_sha256"]:
        raise RuntimeError("harness or executable changed during execution")
    if digest(schedule_path) != schedule_sha256:
        raise RuntimeError("schedule changed during execution")
    harness.write_json(BASE / "results" / f"{args.pass_name}-complete.json",
                       {"status": "PASS" if not failures else "FAILURES_PRESENT", "pass": args.pass_name,
                        "key_sessions": len(tasks), "profile_execution_seconds": profile_execution_seconds,
                        "harness_sha256": stored["combined_sha256"], "execution_identity": stored["execution_identity"],
                        "schedule_sha256": schedule_sha256, "failures": failures})


def selected_correctness_cells():
    selected = []
    fixtures = load(BASE / "fixtures.json")
    for backend, case, profile in cells():
        if not lattice_wide(backend, case):
            continue
        for variant in pilot_variants(backend, case, profile):
            fixture_ids = [fixture["fixture_id"] for fixture in fixtures if fixture["case"] == case]
            selected.append({**variant, "repetitions": 1, "batch_size": 1,
                             "fixture_ids": fixture_ids, "timeout_seconds": 4 * 3600})
    return selected


def session_smoke(args):
    sessions, records = [], []
    for backend, case, profile in cells():
        if profile != 1 or (args.backends and backend not in args.backends):
            continue
        fixture_ids = [fixture["fixture_id"] for fixture in load(BASE / "fixtures.json") if fixture["case"] == case]
        cell = {"backend": backend, "case": case, "profile": profile, "repetitions": 1,
                "batch_size": 1, "fixture_ids": fixture_ids, "timeout_seconds": 4 * 3600}
        run_session("session-smoke", cell, 0)
        sessions.append({"backend": backend, "case": case, "profile": profile, "key": 0,
                         "representation": "coef-binary", "key_switch": "AUTO"})
        for fixture_id in cell["fixture_ids"]:
            records.append(str(cell_directory("session-smoke", cell) / f"key-0-fixture-{fixture_id}.json"))
        harness.write_json(BASE / "results/session-smoke-summary.json", {"sessions": sessions, "records": records})
    selected_sessions, selected_records = [], []
    for cell in selected_correctness_cells():
        run_session("session-smoke-selected", cell, 0)
        selected_sessions.append({**cell, "key": 0})
        for fixture_id in cell["fixture_ids"]:
            selected_records.append(str(cell_directory("session-smoke-selected", cell) / f"key-0-fixture-{fixture_id}.json"))
        sessions.append({key: cell[key] for key in ("backend", "case", "profile", "representation", "key_switch")} | {"key": 0})
        records.extend(selected_records[-len(cell["fixture_ids"]):])
        harness.write_json(BASE / "results/session-smoke-summary.json",
                           {"status": "IN_PROGRESS", "sessions": sessions, "records": records,
                            "selected_sessions": selected_sessions, "selected_records": selected_records})
    manifest = harness.manifest_identity()
    harness.write_json(BASE / "results/session-smoke-summary.json",
                       {"status": "PASS" if not args.backends else "PARTIAL", "sessions": sessions, "records": records,
                        "selected_sessions": selected_sessions, "selected_records": selected_records,
                        "harness_identity": manifest["combined_sha256"], "execution_identity": manifest["execution_identity"],
                        "scope": "baseline plus every selected representation and key-switch over all declared fixtures",
                        "correctness_session_allowance_seconds": 4 * 3600})
    print(json.dumps({"status": "PASS", "key_sessions": len(sessions), "records": len(records),
                      "selected_sessions": len(selected_sessions), "selected_records": len(selected_records)}, allow_nan=False))


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    for name, function in (("pilot", pilot), ("micro", micro), ("session-pilot", session_pilot)):
        p = sub.add_parser(name)
        p.add_argument("--backends", nargs="+", choices=BACKENDS)
        p.add_argument("--force", action="store_true")
        p.add_argument("--gate-timeout", type=int, default=1800)
        p.add_argument("--load-threshold", type=float, default=2.0)
        p.set_defaults(function=function)
    p = sub.add_parser("freeze")
    p.set_defaults(function=freeze)
    p = sub.add_parser("run")
    p.add_argument("--pass", dest="pass_name", choices=("forward", "reverse"), required=True)
    p.add_argument("--gate-timeout", type=int, default=3600)
    p.add_argument("--load-threshold", type=float, default=2.0)
    p.set_defaults(function=long_run)
    p = sub.add_parser("session-smoke")
    p.add_argument("--backends", nargs="+", choices=BACKENDS)
    p.set_defaults(function=session_smoke)
    args = parser.parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
