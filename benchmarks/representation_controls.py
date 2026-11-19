#!/usr/bin/env python3
import copy
import json
from pathlib import Path
import tempfile

import harness
import manifest
import platform_support
import representations
import schedule
import tables


def rejects(function, label, reason=None):
    try:
        function()
    except (RuntimeError, ValueError) as error:
        if reason is not None and reason not in str(error):
            raise AssertionError(f"negative control failed for the wrong reason: {error}")
        return label
    raise AssertionError(f"negative control accepted: {label}")


def main():
    checks = []
    group = {"candidates": [
        {"status": "PASS", "representation": "coef-binary", "key_switch": "HYBRID",
         "eval_median_ms": 1.0, "e2e_median_ms": 10.0},
        {"status": "PASS", "representation": "crt30", "key_switch": "BV",
         "eval_median_ms": 2.0, "e2e_median_ms": 1.0},
    ]}
    representations.choose(group, "bfv", "D25-d4", 1)
    assert len(group["selected"]) == 2
    assert {tuple(sorted(item["roles"])) for item in group["selected"]} == {("e2e",), ("server",)}
    assert schedule.cell_directory("forward", {"backend": "bfv", "case": "D25-d4", "profile": 1,
                                               "representation": "coef-binary", "key_switch": "HYBRID"}) != \
           schedule.cell_directory("forward", {"backend": "bfv", "case": "D25-d4", "profile": 1,
                                               "representation": "coef-binary", "key_switch": "BV"})
    assert tables.result_key({"backend": "bfv", "case": "D25-d4", "profile": 1,
                              "representation": "coef-binary", "key_switch_requested": "HYBRID"}) != \
           tables.result_key({"backend": "bfv", "case": "D25-d4", "profile": 1,
                              "representation": "coef-binary", "key_switch_requested": "BV"})
    checks.append("two-winners-and-distinct-identities")

    from fixtures import WIDE_CASES
    original_base, original_schedule_base = harness.BASE, schedule.BASE
    with tempfile.TemporaryDirectory(dir=BASE / "results") as temporary:
        temporary = Path(temporary)
        harness.BASE = temporary
        schedule.BASE = temporary
        try:
            for case in WIDE_CASES:
                cell = {"backend": "bfv", "case": case, "profile": 1,
                        "representation": "coef-binary", "key_switch": "HYBRID"}
                for seconds, expected_count in ((0.001, 6), (1.5, 6), (10.0, 2), (100.0, 1), (1000.0, 1)):
                    path = schedule.pilot_output("pilot", cell)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    harness.write_json(path, {"eval_ms": [seconds * 1000.0]})
                    selected = schedule.pilot_cell(cell)
                    assert len(selected["fixture_ids"]) == expected_count, (case, seconds, selected["fixture_ids"])
                    assert selected["fixture_ids"][0] == 2
                    assert len(set(selected["fixture_ids"])) == expected_count
            cell = {"backend": "bfv", "case": "I63-add", "profile": 1,
                    "representation": "coef-binary", "key_switch": "HYBRID"}
            for root, value in (("pilot", 0.01), ("pilot-micro", 0.004)):
                path = schedule.pilot_output(root, cell)
                path.parent.mkdir(parents=True, exist_ok=True)
                harness.write_json(path, {"eval_ms": [value], "batch_size": 1000})
            assert schedule.pilot_cell(cell)["batch_size"] == 1000
        finally:
            harness.BASE, schedule.BASE = original_base, original_schedule_base
    checks.append("all-wide-cases-and-sampling-tiers")

    original_topology = platform_support.cpu_topology
    platform_support.cpu_topology = lambda: {"allowed_cpus": list(range(8)), "complete": True, "errors": [], "cpus": [
        {"cpu": cpu, "core_id": cpu // 2, "package_id": 0, "thread_siblings": f"{cpu ^ 1},{cpu}"}
        for cpu in range(8)
    ]}
    try:
        assert platform_support.linux_affinity(1)["cpus"] == [7]
        assert platform_support.linux_affinity(4)["cpus"] == [7, 5, 3, 1]
    finally:
        platform_support.cpu_topology = original_topology
    checks.append("highest-numbered-physical-cores")
    original_observation = platform_support.linux_observation
    original_platform = platform_support.sys.platform
    platform_support.linux_observation = lambda: {"machine": "x86_64", "cpu_flags": ["pclmulqdq"],
                                                   "virtualization": "unavailable: tool missing"}
    platform_support.sys.platform = "linux"
    try:
        rejects(platform_support.require_dedicated_linux, "unavailable virtualization check")
    finally:
        platform_support.linux_observation = original_observation
        platform_support.sys.platform = original_platform
    checks.append("unavailable-virtualization-check-rejected")

    assert platform_support.parse_cpu_list("0-3,6,8-9") == {0, 1, 2, 3, 6, 8, 9}
    original_topology = platform_support.cpu_topology
    platform_support.cpu_topology = lambda: {"allowed_cpus": [0, 1, 2, 3], "complete": True, "errors": [], "cpus": [
        {"cpu": cpu, "core_id": cpu // 2, "package_id": 0, "thread_siblings": f"{cpu ^ 1},{cpu}"}
        for cpu in range(4)
    ]}
    try:
        rejects(lambda: platform_support.linux_affinity(4), "insufficient distinct physical cores")
    finally:
        platform_support.cpu_topology = original_topology
    original_topology = platform_support.cpu_topology
    platform_support.cpu_topology = lambda: {"allowed_cpus": [0, 1, 2, 3], "complete": False,
                                               "errors": ["unreadable topology"], "cpus": []}
    try:
        rejects(lambda: platform_support.linux_affinity(4), "unreadable topology")
    finally:
        platform_support.cpu_topology = original_topology
    checks.append("physical-core-admission-and-range-parsing")
    with tempfile.TemporaryDirectory(dir=BASE / "results") as thermal:
        root = Path(thermal)
        zone = root / "class/thermal/thermal_zone0"
        zone.mkdir(parents=True)
        (zone / "type").write_text("cpu\n")
        (zone / "trip_point_0_type").write_text("critical\n")
        (zone / "trip_point_0_temp").write_text("100000\n")
        (zone / "temp").write_text("30000\n")
        assert platform_support.thermal_observation(root)["ok"] is True
        (zone / "temp").write_text("120000\n")
        assert platform_support.thermal_observation(root)["ok"] is False
        (zone / "temp").write_text("30000\n")
        (zone / "trip_point_0_temp").write_text("unreadable\n")
        assert platform_support.thermal_observation(root)["ok"] is True
        (zone / "temp").write_text("90000\n")
        assert platform_support.thermal_observation(root)["ok"] is False
        empty = root / "empty"
        empty.mkdir()
        assert platform_support.thermal_observation(empty)["ok"] is False
        missing = root / "missing-root"
        (missing / "class/thermal/thermal_zone0").mkdir(parents=True)
        (missing / "class/thermal/thermal_zone0/temp").write_text("90000\n")
        assert platform_support.thermal_observation(missing)["ok"] is False
        (missing / "class/thermal/thermal_zone0/temp").write_text("30000\n")
        assert platform_support.thermal_observation(missing)["ok"] is True
        (zone / "trip_point_0_temp").write_text("100000\n")
        hwmon = root / "class/hwmon/hwmon0"
        hwmon.mkdir(parents=True)
        (hwmon / "temp1_input").write_text("30000\n")
        (hwmon / "temp1_max").write_text("100000\n")
        assert platform_support.thermal_observation(root)["ok"] is True
        amd = root / "amd"
        cpu = amd / "class/hwmon/hwmon0"
        nvme = amd / "class/hwmon/hwmon1"
        cpu.mkdir(parents=True)
        nvme.mkdir(parents=True)
        (cpu / "temp1_input").write_text("38000\n")
        (cpu / "temp3_input").write_text("45000\n")
        (nvme / "temp1_input").write_text("40000\n")
        (nvme / "temp1_max").write_text("100000\n")
        (nvme / "temp2_input").write_text("42000\n")
        assert platform_support.thermal_observation(amd)["ok"] is True
        (cpu / "temp3_input").write_text("90000\n")
        assert platform_support.thermal_observation(amd)["ok"] is False
        limit_root = root / "limit-root"
        limit = limit_root / "class/hwmon/hwmon0"
        limit.mkdir(parents=True)
        (limit / "temp1_input").write_text("105000\n")
        (limit / "temp1_max").write_text("120000\n")
        (limit / "temp1_crit").write_text("100000\n")
        observation = platform_support.thermal_observation(limit_root)
        assert len(observation["zones"]) == 1
        assert observation["zones"][0]["critical_millicelsius"] == 100000
        assert observation["zones"][0]["threshold_source"] == "temp1_crit"
        assert observation["ok"] is False
    checks.append("thermal-healthy-hot-and-unreadable-controls")
    checks.append("thermal-empty-missing-threshold-and-hwmon-controls")
    checks.append("thermal-amd-fallback-and-stricter-limit-controls")

    with tempfile.TemporaryDirectory(dir=BASE / "results") as temporary:
        temporary = Path(temporary)
        groups = {}
        for backend, case, profile in representations.required_groups():
            key_switches = ["HYBRID", "BV"] if backend == "bfv" and case == "D25-d4" and profile == 1 else ["HYBRID"]
            selected = [{"representation": "coef-binary", "key_switch": key_switch, "roles": ["server"]}
                        for key_switch in key_switches]
            groups[representations.group_name(backend, case, profile)] = {"status": "PASS", "selected": selected, "candidates": []}
        groups[representations.group_name("bgv", "F127-mul", 4)]["selected"] = [
            {"representation": "crt30", "key_switch": "HYBRID", "roles": ["server"]}
        ]
        selection = {"status": "PASS", "groups": groups, "selection_metric": "mock control"}
        selection_path = temporary / "selection.json"
        harness.write_json(selection_path, selection)
        original_selection = representations.SELECTION
        original_identity = harness.manifest_identity
        original_fingerprint = manifest.current_fingerprint
        representations.SELECTION = selection_path
        harness.manifest_identity = lambda: {"combined_sha256": "CURRENT", "execution_identity": "EXECUTABLE"}
        manifest.current_fingerprint = lambda: "CURRENT"
        try:
            cells = []
            for backend, case, profile in schedule.cells():
                selected = groups[representations.group_name(backend, case, profile)]["selected"] if schedule.lattice_wide(backend, case) else [
                    {"representation": "coef-binary", "key_switch": "AUTO", "roles": ["native"]}
                ]
                for variant in selected:
                    cells.append({"backend": backend, "case": case, "profile": profile,
                                  "representation": variant["representation"], "key_switch": variant["key_switch"],
                                  "keys": 1, "repetitions": 1, "batch_size": 1, "timeout_seconds": 1800,
                                  "fixture_ids": [0]})
            selected_cells = schedule.selected_correctness_cells()
            assert sum(cell["backend"] == "bfv" and cell["case"] == "D25-d4" and cell["profile"] == 1
                       for cell in selected_cells) == 2
            assert any(cell["backend"] == "bgv" and cell["case"] == "F127-mul" and
                       cell["profile"] == 4 and cell["representation"] == "crt30" for cell in selected_cells)
            selected_session_entries = [{**cell, "key": 0} for cell in selected_cells]
            harness.BASE = temporary
            schedule.BASE = temporary
            harness.write_json(temporary / "fixtures.json", harness.load_json(original_base / "fixtures.json"))
            harness.write_json(temporary / "results/session-smoke-summary.json", {
                "harness_identity": "CURRENT", "execution_identity": "EXECUTABLE",
                "selected_sessions": selected_session_entries, "selected_records": [],
            })
            rejects(lambda: schedule.validate_selected_sessions({"combined_sha256": "CURRENT", "execution_identity": "EXECUTABLE"}),
                    "missing selected correctness records")
            source_record = harness.load_json(original_base / "results/native-matrix/bfv-D25-d4-crt30-HYBRID.json")
            selected_paths = []
            for cell in selected_cells:
                for index, fixture_id in enumerate(cell["fixture_ids"]):
                    path = schedule.cell_directory("session-smoke-selected", cell) / f"key-0-fixture-{fixture_id}.json"
                    selected_paths.append(path)
                    invalid = copy.deepcopy(source_record)
                    invalid["status"] = "PASS"
                    invalid["harness_identity"] = "CURRENT"
                    invalid["execution_identity"] = "EXECUTABLE"
                    invalid["fixture_sha256"] = harness.sha256_file(temporary / "fixtures.json")
                    invalid["rusage_evidence"] = "results/rusage.json"
                    invalid["parameter_sha256"] = harness.parameter_identity(invalid)
                    invalid["backend"] = cell["backend"]
                    invalid["case"] = cell["case"]
                    invalid["profile"] = cell["profile"]
                    invalid["representation"] = cell["representation"]
                    invalid["key_switch_requested"] = cell["key_switch"]
                    invalid["key_switch_technique"] = cell["key_switch"]
                    if invalid["key_switch_technique"] == "AUTO":
                        invalid["key_switch_technique"] = "BV" if cell["backend"] == "bfv" and cell["case"].startswith("D25") else "HYBRID"
                    invalid["key_process_id"] = schedule.key_process_id("session-smoke-selected", cell, 0)
                    invalid["fixture_index"] = index
                    invalid["fixture_count"] = len(cell["fixture_ids"])
                    if cell["case"] == "I63-add" and fixture_id == 1:
                        invalid["fixture"] = next(item for item in harness.load_json(temporary / "fixtures.json")
                                                  if item["case"] == "I63-add" and item["fixture_id"] == 3)
                        invalid["values_decimal"] = [str(1 << 63)]
                        invalid["lift_decimal"] = [str(1 << 63)]
                    harness.write_json(path, invalid)
            harness.write_json(temporary / "results/rusage.json",
                               harness.load_json(original_base / "results/native-matrix/bfv-D25-d4-crt30-HYBRID.json.rusage.json"))
            harness.write_json(temporary / "results/session-smoke-summary.json", {
                "harness_identity": "CURRENT", "execution_identity": "EXECUTABLE",
                "selected_sessions": selected_session_entries,
                "selected_records": [str(path) for path in selected_paths],
            })
            rejects(lambda: schedule.validate_selected_sessions({"combined_sha256": "CURRENT", "execution_identity": "EXECUTABLE"}),
                    "mixed selected record identities", "fixture mismatch")
            harness.write_json(temporary / "results/session-smoke-summary.json", {
                "harness_identity": "CURRENT", "execution_identity": "EXECUTABLE",
                "selected_sessions": selected_session_entries + [selected_session_entries[0]],
                "selected_records": [],
            })
            rejects(lambda: schedule.validate_selected_sessions({"combined_sha256": "CURRENT", "execution_identity": "EXECUTABLE"}),
                    "duplicated selected session")
            harness.BASE, schedule.BASE = original_base, original_schedule_base
            checks.append("selected-coverage-and-missing-record-rejected")
            checks.append("mixed-record-and-duplicate-session-rejected")
            document = {"status": "frozen", "harness_sha256": "CURRENT", "execution_identity": "EXECUTABLE",
                        "representation_selection_sha256": harness.sha256_file(selection_path),
                        "profile_budget_seconds": 21600, "schedule": cells}
            schedule_path = temporary / "schedule.json"
            harness.write_json(schedule_path, document)
            _, loaded, _ = schedule.frozen_schedule(schedule_path)
            assert len(loaded["schedule"]) == len(cells)
            assert sum(cell["case"] == "D25-d4" and cell["backend"] == "bfv" and cell["profile"] == 1
                       for cell in loaded["schedule"]) == 2
            checks.append("frozen-schedule-admits-selected-variants")
            valid_document = copy.deepcopy(document)
            stale = copy.deepcopy(valid_document)
            stale["representation_selection_sha256"] = "0" * 64
            harness.write_json(schedule_path, stale)
            rejects(lambda: schedule.frozen_schedule(schedule_path), "stale selection hash")
            checks.append("stale-selection-rejected")
            harness.write_json(schedule_path, document)
            for cell in cells:
                if cell["backend"] == "bfv" and cell["case"] == "D25-d4" and cell["profile"] == 1:
                    cell["representation"] = "crt30"
                    break
            harness.write_json(schedule_path, document)
            rejects(lambda: schedule.frozen_schedule(schedule_path), "unselected representation")
            checks.append("unselected-representation-rejected")
            missing = copy.deepcopy(valid_document)
            missing["schedule"] = [cell for cell in missing["schedule"]
                                   if not (cell["backend"] == "bfv" and cell["case"] == "D25-d4" and
                                           cell["profile"] == 1 and cell["key_switch"] == "BV")]
            harness.write_json(schedule_path, missing)
            rejects(lambda: schedule.frozen_schedule(schedule_path), "missing selected winner", "scheduled variant set differs")
            checks.append("missing-selected-winner-rejected")
            duplicate = copy.deepcopy(valid_document)
            duplicate["schedule"].append(next(cell for cell in duplicate["schedule"]
                                              if cell["backend"] == "bfv" and cell["case"] == "D25-d4" and
                                              cell["profile"] == 1 and cell["key_switch"] == "BV"))
            harness.write_json(schedule_path, duplicate)
            rejects(lambda: schedule.frozen_schedule(schedule_path), "duplicate selected winner")
            checks.append("duplicate-selected-winner-rejected")
        finally:
            representations.SELECTION = original_selection
            harness.manifest_identity = original_identity
            manifest.current_fingerprint = original_fingerprint
    report = {"status": "PASS", "checks": checks, "scope": "mock-only selection and schedule controls, no engines"}
    harness.write_json(BASE / "results/representation-controls.json", report)
    print(json.dumps(report, indent=2))


BASE = harness.BASE


if __name__ == "__main__":
    main()
