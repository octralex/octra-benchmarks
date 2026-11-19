#!/usr/bin/env python3
import datetime
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def capture(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
        text = result.stdout.strip()
        return text if text else f"unavailable: exit {result.returncode}: {result.stderr.strip()}"
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"unavailable: {error}"


def read_text(path):
    try:
        return Path(path).read_text().strip()
    except OSError as error:
        return f"unavailable: {error}"


def cpu_flags():
    if sys.platform == "darwin":
        return capture(["sysctl", "-n", "machdep.cpu.features"]).split()
    if sys.platform.startswith("linux"):
        for line in read_text("/proc/cpuinfo").splitlines():
            if line.startswith(("flags", "Features")) and ":" in line:
                return line.split(":", 1)[1].split()
    return []


def cpu_topology(allowed=None):
    if allowed is None:
        allowed = sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else list(range(os.cpu_count() or 1))
    groups = []
    errors = []
    for cpu in allowed:
        siblings = read_text(f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list")
        core_id = read_text(f"/sys/devices/system/cpu/cpu{cpu}/topology/core_id")
        package_id = read_text(f"/sys/devices/system/cpu/cpu{cpu}/topology/physical_package_id")
        try:
            sibling_set = parse_cpu_list(siblings)
            if cpu not in sibling_set:
                raise ValueError("CPU is absent from its sibling set")
            core_number = int(core_id)
            package_number = int(package_id)
            if core_number < 0 or package_number < 0:
                raise ValueError("negative topology identifier")
        except (ValueError, TypeError):
            errors.append(f"cpu{cpu}: unreadable or inconsistent topology")
            sibling_set = set()
            core_number = -1
            package_number = -1
        groups.append({"cpu": cpu, "core_id": core_id, "package_id": package_id,
                       "core_number": core_number, "package_number": package_number,
                       "thread_siblings": siblings, "sibling_set": sorted(sibling_set)})
    return {"allowed_cpus": allowed, "cpus": groups, "complete": not errors, "errors": errors}


def parse_cpu_list(text):
    cpus = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        bounds = part.split("-", 1)
        if len(bounds) == 1:
            cpus.add(int(bounds[0]))
            continue
        first, last = map(int, bounds)
        if last < first:
            raise ValueError(f"invalid CPU range: {part}")
        cpus.update(range(first, last + 1))
    return cpus


def linux_affinity(workers):
    if workers not in (1, 4):
        raise ValueError("worker profile must be 1 or 4")
    topology = cpu_topology()
    if not topology.get("complete", False):
        raise RuntimeError(f"unreadable or inconsistent CPU topology: {topology.get('errors')}")
    selected = []
    seen_cores = set()
    for entry in reversed(topology["cpus"]):
        core = (entry["package_id"], entry["core_id"])
        if core not in seen_cores:
            selected.append(entry["cpu"])
            seen_cores.add(core)
        if len(selected) == workers:
            break
    if len(selected) != workers:
        raise RuntimeError(f"{workers}-worker profile requires {workers} distinct physical cores, SMT fallback is not admitted")
    sibling_count = 0
    for entry in topology["cpus"]:
        if entry["cpu"] in selected:
            siblings = set(entry.get("sibling_set", parse_cpu_list(entry["thread_siblings"])))
            sibling_count += len(siblings.intersection(selected)) - 1
    if sibling_count:
        raise RuntimeError("selected CPU set contains SMT siblings despite distinct-core selection")
    return {
        "cpus": selected,
        "taskset": ["taskset", "-c", ",".join(map(str, selected))],
        "smt_siblings_used": sibling_count > 0,
        "selection_policy": "highest-numbered distinct physical cores, no SMT fallback",
        "topology": topology,
    }


def meminfo():
    result = {}
    for line in read_text("/proc/meminfo").splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1].isdigit():
            result[fields[0].rstrip(":")] = int(fields[1]) * 1024
    return result


def thermal_observation(root=Path("/sys")):
    zones = []

    def threshold(paths):
        values = []
        for path in paths:
            try:
                values.append((int(path.read_text().strip()), path.name))
            except (OSError, ValueError):
                continue
        return min(values) if values else (None, None)

    for zone in sorted((root / "class/thermal").glob("thermal_zone*")):
        try:
            temperature = int((zone / "temp").read_text().strip())
        except (OSError, ValueError):
            continue
        record = {"zone": zone.name, "type": read_text(zone / "type"), "temperature_millicelsius": temperature}
        thresholds = []
        for trip in sorted(zone.glob("trip_point_*_type")):
            if read_text(trip) != "critical":
                continue
            match = re.fullmatch(r"trip_point_(\d+)_type", trip.name)
            if match is not None:
                value, source = threshold([zone / f"trip_point_{match.group(1)}_temp"])
                if value is not None:
                    thresholds.append((value, source))
        if thresholds:
            record["critical_millicelsius"], record["threshold_source"] = min(thresholds)
        else:
            record["critical_millicelsius"] = 85000
            record["threshold_source"] = "declared_default"
        zones.append(record)
    for sensor in sorted((root / "class/hwmon").glob("hwmon*/temp*_input")):
        try:
            temperature = int(sensor.read_text().strip())
        except (OSError, ValueError):
            continue
        prefix = sensor.name.removesuffix("_input")
        value, source = threshold([sensor.with_name(f"{prefix}_max"), sensor.with_name(f"{prefix}_crit")])
        record = {"zone": f"{sensor.parent.name}/{sensor.name}", "type": "hwmon",
                  "temperature_millicelsius": temperature}
        if value is not None:
            record["critical_millicelsius"] = value
            record["threshold_source"] = source
        else:
            record["critical_millicelsius"] = 85000
            record["threshold_source"] = "declared_default"
        zones.append(record)
    counters = {}
    for path in sorted((root / "devices/system/cpu").glob("cpu[0-9]*/thermal_throttle/*")):
        counters[str(path)] = read_text(path)
    thermal_ok = bool(zones) and all("critical_millicelsius" in record and
                                    record["temperature_millicelsius"] < record["critical_millicelsius"]
                                    for record in zones)
    return {"zones": zones, "throttle_counters": counters, "ok": thermal_ok,
            "declared_ceiling_millicelsius": 85000,
            "policy": "below the stricter sensor limit when present, otherwise below declared_default 85000, empty observations rejected"}


def linux_observation():
    memory = meminfo()
    thermal = thermal_observation()
    governors = {
        path.parent.parent.name: read_text(path)
        for path in sorted(Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq/scaling_governor"))
    }
    turbo = {
        "cpufreq_boost": read_text("/sys/devices/system/cpu/cpufreq/boost"),
        "intel_no_turbo": read_text("/sys/devices/system/cpu/intel_pstate/no_turbo"),
    }
    flags = cpu_flags()
    return {
        "time": utc(),
        "platform": sys.platform,
        "loadavg": list(os.getloadavg()),
        "thermal": thermal,
        "thermal_ok": thermal["ok"],
        "power": "AC state is not a laptop-battery gate on Linux",
        "swap_used_bytes": memory.get("SwapTotal", 0) - memory.get("SwapFree", 0),
        "memory": memory,
        "cpu_brand": capture(["sh", "-c", "lscpu | sed -n 's/^Model name:[[:space:]]*//p'"]),
        "cpu_flags": flags,
        "avx512_host": all(flag in flags for flag in ("avx512f", "avx512dq", "avx512bw", "avx512vl")),
        "frequency_governors": governors,
        "turbo_boost": turbo,
        "cpu_pinning": "taskset with recorded logical CPUs and SMT topology",
        "sleep_prevention": "systemd-inhibit --what=sleep for supervised measurement stages",
        "virtualization": capture(["systemd-detect-virt"]),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "load_threshold": 2.0,
        "cpu_time_limit": "none, wall timeout enforced",
    }


def darwin_observation():
    swap = capture(["sysctl", "vm.swapusage"])
    try:
        swap_used = float(swap.split("used =", 1)[1].split()[0].rstrip("M")) * 1024 * 1024
    except (IndexError, ValueError):
        swap_used = float("inf")
    thermal = capture(["pmset", "-g", "therm"])
    return {
        "time": utc(),
        "platform": sys.platform,
        "loadavg": list(os.getloadavg()),
        "thermal": thermal,
        "thermal_ok": ("No thermal warning level has been recorded" in thermal and
                       "No performance warning level has been recorded" in thermal),
        "power": capture(["pmset", "-g", "ps"]),
        "swap_used_bytes": swap_used,
        "memory_pressure": capture(["memory_pressure"]),
        "cpu_brand": capture(["sysctl", "-n", "machdep.cpu.brand_string"]),
        "cpu_pinning": "unsupported on this macOS venue, no taskset or affinity claim",
        "sleep_prevention": "caffeinate -i on each measured child, supervisor must also run under caffeinate",
        "virtualization": "not_applicable",
        "kernel": platform.release(),
        "machine": platform.machine(),
        "load_threshold": 2.0,
        "cpu_time_limit": "none, wall timeout enforced",
    }


def observation():
    if sys.platform == "darwin":
        return darwin_observation()
    if sys.platform.startswith("linux"):
        return linux_observation()
    raise RuntimeError(f"unsupported platform: {sys.platform}")


def quiet_status(observation, threshold, require_ac=True):
    ac_power = True
    if observation["platform"] == "darwin":
        ac_power = "Now drawing from 'AC Power'" in observation["power"]
    return {
        "load_ok": observation["loadavg"][0] < threshold,
        "ac_power": ac_power or not require_ac,
        "thermal_ok": observation["thermal_ok"],
        "swap_used_bytes": observation["swap_used_bytes"],
        "swap_ok": observation["swap_used_bytes"] == 0,
    }


def require_dedicated_linux():
    if not sys.platform.startswith("linux"):
        return
    current = linux_observation()
    problems = []
    if current["machine"] not in ("x86_64", "AMD64"):
        problems.append("Linux timing requires x86-64")
    if "pclmulqdq" not in current["cpu_flags"] and "pclmul" not in current["cpu_flags"]:
        problems.append("carry-less multiplication is unavailable")
    virtualization = current["virtualization"].strip().lower()
    if virtualization != "none":
        problems.append(f"virtualized venue or unavailable virtualization check rejected: {current['virtualization']}")
    if problems:
        raise RuntimeError(", ".join(problems))


def tfhe_avx512_build():
    flags = cpu_flags()
    required = {"avx512f", "avx512dq", "avx512bw", "avx512vl"}
    return sys.platform.startswith("linux") and platform.machine() in ("x86_64", "AMD64") and required.issubset(flags)


def tfhe_executable_info(binary):
    document = json.loads(capture([str(binary), "--build-info"]))
    for field in ("avx512_feature_compiled", "avx512_runtime_eligible"):
        if type(document.get(field)) is not bool:
            raise RuntimeError(f"TFHE build info lacks boolean {field}")
    expected = tfhe_avx512_build()
    if (document["avx512_feature_compiled"] != expected or document["avx512_runtime_eligible"] != expected):
        raise RuntimeError(f"TFHE executable and host AVX-512 identities differ: {document}, host eligible={expected}")
    document["avx512_host_eligible"] = expected
    return document


def avx512_instruction_evidence(binary):
    if not sys.platform.startswith("linux"):
        return {"status": "not_applicable"}
    disassembly = capture(["objdump", "-d", str(binary)])
    zmm = len(re.findall(r"%zmm\d+", disassembly))
    opmask = len(re.findall(r"%k[0-7]\b", disassembly))
    return {
        "zmm_operand_references": zmm,
        "opmask_operand_references": opmask,
        "contains_avx512_instruction_operands": zmm > 0,
        "scope": "static compiled-binary evidence, not a runtime instruction count",
    }


def main():
    if sys.argv[1:] == ["--tfhe-avx512-only"]:
        raise SystemExit(0 if tfhe_avx512_build() else 1)
    if sys.argv[1:]:
        raise SystemExit("usage: platform_support.py [--tfhe-avx512-only]")
    print(json.dumps({"host": observation(), "tfhe_avx512_build": tfhe_avx512_build()}, indent=2))


if __name__ == "__main__":
    main()
