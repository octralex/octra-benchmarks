#!/usr/bin/env python3
import argparse
import json
import statistics

import harness
import schedule

BASE = harness.BASE
SELECTION = BASE / "results/representation-selection.json"


def candidates(backend, case, profile):
    grid = harness.load_json(BASE / "wide-candidates.json")
    result = []
    for candidate in grid["cases"][case]:
        representation = candidate["representation"]
        for key_switch in candidate["key_switch_candidates"][backend]:
            result.append({
                "backend": backend,
                "case": case,
                "profile": profile,
                "representation": representation,
                "key_switch": key_switch,
                "fixture_file": "calibration-fixtures.json",
                "fixture_ids": [0, 1],
                "repetitions": 3,
                "batch_size": 1,
                "timeout_seconds": 1800,
            })
    return result


def required_groups():
    from fixtures import WIDE_CASES
    return {(backend, case, profile) for backend in ("bfv", "bgv") for case in WIDE_CASES for profile in (1, 4)}


def group_name(backend, case, profile):
    return f"{backend}|{case}|{profile}"


def median(values):
    return statistics.median(values)


def candidate_result(cell):
    directory = schedule.cell_directory("pilot-candidates", cell)
    paths = [directory / f"key-0-fixture-{fixture_id}.json" for fixture_id in cell["fixture_ids"]]
    records = [harness.load_json(path) for path in paths]
    fixtures = {fixture["fixture_id"]: fixture for fixture in harness.load_json(BASE / "calibration-fixtures.json")
                if fixture["case"] == cell["case"]}
    for index, record in enumerate(records):
        harness.validate(record, fixtures[cell["fixture_ids"][index]], check_identity=True)
    eval_samples = [value for record in records for value in record["eval_ms"]]
    e2e_samples = [record["e2e_ms"] for record in records]
    return {
        "status": "PASS",
        "representation": cell["representation"],
        "key_switch": cell["key_switch"],
        "eval_median_ms": median(eval_samples),
        "e2e_median_ms": median(e2e_samples),
        "per_fixture_eval_median_ms": [median(record["eval_ms"]) for record in records],
        "per_fixture_e2e_ms": e2e_samples,
        "evidence": [str(path.relative_to(BASE)) for path in paths],
    }


def choose(document, backend, case, profile):
    passing = [candidate for candidate in document["candidates"] if candidate["status"] == "PASS"]
    if not passing:
        raise RuntimeError(f"no correct candidate for {backend} {case} profile {profile}")
    server = min(passing, key=lambda candidate: (candidate["eval_median_ms"], candidate["e2e_median_ms"],
                                                candidate["representation"], candidate["key_switch"]))
    e2e = min(passing, key=lambda candidate: (candidate["e2e_median_ms"], candidate["eval_median_ms"],
                                              candidate["representation"], candidate["key_switch"]))
    selected = []
    for role, candidate in (("server", server), ("e2e", e2e)):
        identity = candidate["representation"], candidate["key_switch"]
        existing = next((item for item in selected if (item["representation"], item["key_switch"]) == identity), None)
        if existing:
            existing["roles"].append(role)
        else:
            selected.append({"representation": identity[0], "key_switch": identity[1], "roles": [role]})
    document["selected"] = selected
    document["server_winner"] = {"representation": server["representation"], "key_switch": server["key_switch"]}
    document["e2e_winner"] = {"representation": e2e["representation"], "key_switch": e2e["key_switch"]}


def select(args):
    document = harness.load_json(SELECTION) if SELECTION.exists() else {
        "status": "IN_PROGRESS",
        "selection_metric": harness.load_json(BASE / "wide-candidates.json")["selection_metric"],
        "groups": {},
    }
    if document.get("status") == "FROZEN":
        raise RuntimeError("representation selection is already frozen")
    for backend, case, profile in sorted(required_groups()):
        name = group_name(backend, case, profile)
        group = document["groups"].setdefault(name, {"candidates": []})
        retained = {(candidate["representation"], candidate["key_switch"]): candidate for candidate in group["candidates"]}
        observations = []
        for cell in candidates(backend, case, profile):
            identity = cell["representation"], cell["key_switch"]
            if identity in retained and retained[identity]["status"] == "PASS" and not args.force:
                observations.append(candidate_result(cell))
                continue
            harness.wait_for_quiet(args.gate_timeout, args.load_threshold)
            try:
                schedule.run_session("pilot-candidates", cell, 0)
                observations.append(candidate_result(cell))
            except Exception as error:
                observations.append({
                    "status": "REJECTED",
                    "representation": cell["representation"],
                    "key_switch": cell["key_switch"],
                    "error": str(error),
                    "evidence_directory": str(schedule.cell_directory("pilot-candidates", cell).relative_to(BASE)),
                })
            group["candidates"] = observations
            group["status"] = "IN_PROGRESS"
            harness.write_json(SELECTION, document)
        choose(group, backend, case, profile)
        group["status"] = "PASS"
        harness.write_json(SELECTION, document)
    document["status"] = "PASS"
    harness.write_json(SELECTION, document)
    print(json.dumps({"status": "PASS", "groups": len(document["groups"]),
                      "candidates": sum(len(group["candidates"]) for group in document["groups"].values()),
                      "selected": sum(len(group["selected"]) for group in document["groups"].values())}, indent=2))


def require_selection():
    document = harness.load_json(SELECTION)
    if document.get("status") != "PASS" or set(document.get("groups", {})) != {group_name(*group) for group in required_groups()}:
        raise RuntimeError("run representations.py before the lattice pilot")
    for name, group in document["groups"].items():
        if group.get("status") != "PASS" or not group.get("selected"):
            raise RuntimeError(f"representation selection is incomplete: {name}")
    return document


def selected_cells(backend, case, profile):
    document = require_selection()
    group = document["groups"][group_name(backend, case, profile)]
    result = []
    for selected in group["selected"]:
        result.append({
            "representation": selected["representation"],
            "key_switch": selected["key_switch"],
            "selection_roles": selected["roles"],
        })
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--gate-timeout", type=int, default=1800)
    parser.add_argument("--load-threshold", type=float, default=2.0)
    args = parser.parse_args()
    select(args)


if __name__ == "__main__":
    main()
