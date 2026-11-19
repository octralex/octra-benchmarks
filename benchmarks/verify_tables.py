#!/usr/bin/env python3
import copy
import json
import math
import statistics
import sys
from pathlib import Path

RESULTS = Path(__file__).resolve().parent / "results"
PHASES = ("eval_ms", "decrypt_ms", "encryption_ms", "e2e_ms", "setup_ms", "output_bytes", "peak_rss_kib")
STATS = ("n", "median", "q1", "q3", "iqr", "min", "max")
WIDE_CASES = ("I63-add", "I63-mul", "F127-add", "F127-mul", "D25-d1", "D25-d2", "D25-d4")
PASSES = ("forward", "reverse")


class Invalid(Exception):
    pass


def reject_constant(value):
    raise Invalid(f"nonfinite JSON constant: {value}")


def load(path):
    return json.loads(Path(path).read_text(), parse_constant=reject_constant)


def number(value, where, minimum=0.0):
    if type(value) not in (int, float) or not math.isfinite(value) or value < minimum:
        raise Invalid(f"not a finite number at or above {minimum}: {where}")
    return value


def quantile(values, fraction):
    position = (len(values) - 1) * fraction
    lower, upper = math.floor(position), math.ceil(position)
    return values[lower] + (values[upper] - values[lower]) * (position - lower)


def summarize(values):
    values = sorted(values)
    q1, q3 = quantile(values, 0.25), quantile(values, 0.75)
    return {"n": len(values), "median": statistics.median(values), "q1": q1, "q3": q3, "iqr": q3 - q1,
            "min": values[0], "max": values[-1]}


def rebuild(sessions, name):
    cells = {}
    seen = set()
    for session in sessions:
        identity = (session["backend"], session["case"], session["profile"],
                    session.get("representation"), session.get("key_switch_requested"))
        key = identity + (session["key"],)
        if key in seen:
            raise Invalid(f"{name}: duplicate key session {key}")
        seen.add(key)
        peak = number(session["process_peak_rss_bytes"], f"{name} {key} peak", 1)
        if type(peak) is not int:
            raise Invalid(f"{name} {key}: peak memory is not an integer")
        fixtures = session["fixtures"]
        ids = [fixture["fixture_id"] for fixture in fixtures]
        if not fixtures or len(ids) != len(set(ids)):
            raise Invalid(f"{name} {key}: empty or duplicate fixtures")
        cell = cells.setdefault(identity, {phase: [] for phase in PHASES})
        for index, fixture in enumerate(fixtures):
            where = f"{name} {key} fixture {fixture['fixture_id']}"
            counts = {len(fixture[field]) for field in ("eval_ms", "decrypt_ms", "output_bytes")}
            if len(counts) != 1 or 0 in counts:
                raise Invalid(f"sample counts differ or are empty: {where}")
            for field in ("eval_ms", "decrypt_ms", "output_bytes"):
                for value in fixture[field]:
                    number(value, f"{where} {field}")
                cell[field] += fixture[field]
            cell["encryption_ms"].append(number(fixture["encryption_ms"], f"{where} encryption_ms"))
            cell["e2e_ms"].append(number(fixture["e2e_ms"], f"{where} e2e_ms"))
            cell["peak_rss_kib"].append(peak // 1024)
            if (fixture["setup_ms"] is None) != (index != 0):
                raise Invalid(f"setup must be reported for the first fixture of a session only: {where}")
            if fixture["setup_ms"] is not None:
                cell["setup_ms"].append(number(fixture["setup_ms"], f"{where} setup_ms"))
    return {key: {phase: summarize(values) for phase, values in cell.items()} for key, cell in cells.items()}, len(seen)


def verify(samples, tables):
    compared = 0
    failures = []
    for name in PASSES:
        mine, sessions = rebuild(samples["passes"][name], name)
        receipt = tables[name + "_receipt"]
        if receipt.get("status") != "PASS" or receipt.get("key_sessions") != sessions:
            raise Invalid(f"{name}: receipt is not a pass over {sessions} key sessions")
        if receipt.get("harness_sha256") != samples.get("harness_sha256"):
            raise Invalid(f"{name}: samples and tables come from different harness identities")
        rows = {}
        for row in tables[name]:
            lattice_wide = row["backend"] in ("bfv", "bgv") and row["case"] in WIDE_CASES
            key = (row["backend"], row["case"], row["profile"],
                   row.get("representation") if lattice_wide else None,
                   row.get("key_switch_requested") if lattice_wide else None)
            if key in rows:
                raise Invalid(f"{name}: duplicate table row {key}")
            if row.get("status") != "MEASURED":
                raise Invalid(f"{name}: row is not a measured row {key}")
            rows[key] = row
        if set(rows) != set(mine):
            raise Invalid(f"{name}: cell sets differ")
        for key, row in rows.items():
            for phase in PHASES:
                for stat in STATS:
                    compared += 1
                    left = mine[key][phase][stat]
                    right = number(row[phase][stat], f"{name} {key} {phase} {stat}")
                    if abs(left - right) > 1e-12 * max(1.0, abs(right)):
                        failures.append(f"{name} {key} {phase} {stat}: {left} != {right}")
    return compared, failures


def outcome(samples, tables):
    try:
        compared, failures = verify(samples, tables)
    except (Invalid, KeyError, TypeError) as error:
        return "invalid", 0, [repr(error)]
    return ("fail" if failures else "pass"), compared, failures


def self_test(samples, tables):
    cases = {}
    cases["clean"] = (copy.deepcopy(samples), copy.deepcopy(tables), "pass")
    t = copy.deepcopy(tables)
    t["forward"][0]["eval_ms"]["median"] = float("nan")
    cases["nan_median"] = (copy.deepcopy(samples), t, "invalid")
    t = copy.deepcopy(tables)
    t["reverse"].append(copy.deepcopy(t["reverse"][0]))
    cases["duplicate_row"] = (copy.deepcopy(samples), t, "invalid")
    t = copy.deepcopy(tables)
    t["forward"][3]["decrypt_ms"]["iqr"] += 1.0
    cases["changed_iqr"] = (copy.deepcopy(samples), t, "fail")
    s = copy.deepcopy(samples)
    s["passes"]["reverse"][5]["fixtures"][0]["eval_ms"][0] *= 1.5
    cases["changed_sample"] = (s, copy.deepcopy(tables), "fail")
    s = copy.deepcopy(samples)
    s["passes"]["forward"].append(copy.deepcopy(s["passes"]["forward"][0]))
    cases["duplicate_session"] = (s, copy.deepcopy(tables), "invalid")
    s = copy.deepcopy(samples)
    s["passes"]["forward"][7]["fixtures"][0]["eval_ms"][0] = float("inf")
    cases["infinite_sample"] = (s, copy.deepcopy(tables), "invalid")
    s = copy.deepcopy(samples)
    s["passes"]["forward"][9]["fixtures"][0]["decrypt_ms"].pop()
    cases["truncated_samples"] = (s, copy.deepcopy(tables), "invalid")
    s = copy.deepcopy(samples)
    s["harness_sha256"] = "0" * 64
    cases["other_harness"] = (s, copy.deepcopy(tables), "invalid")
    report = {name: {"expected": expected, "observed": outcome(left, right)[0]}
              for name, (left, right, expected) in cases.items()}
    return report, all(entry["expected"] == entry["observed"] for entry in report.values())


def main():
    samples = load(RESULTS / "samples.json")
    tables = load(RESULTS / "tables.json")
    if sys.argv[1:] == ["--self-test"]:
        report, passed = self_test(samples, tables)
        print(json.dumps({"event": "verify_tables_self_test", "status": "pass" if passed else "fail",
                          "cases": report}, allow_nan=False))
        return 0 if passed else 1
    status, compared, failures = outcome(samples, tables)
    print(json.dumps({"event": "verify_tables", "status": status, "compared": compared,
                      "phases": list(PHASES), "statistics": list(STATS), "failures": failures[:20]}, allow_nan=False))
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
