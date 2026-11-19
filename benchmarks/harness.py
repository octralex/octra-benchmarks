#!/usr/bin/env python3
import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from fixtures import CASES
import platform_support

BASE = Path(__file__).resolve().parent
RESULTS = BASE / "results"
SMALL_BACKENDS = ("pvac", "bfv", "bgv", "ckks", "tfhe16", "tfhe64")
WIDE_BACKENDS = ("pvac", "bfv", "bgv", "tfhe-wide")
BACKENDS = SMALL_BACKENDS + ("tfhe-wide",)
MEMORY_LIMIT_KIB = 8 * 1024 * 1024
SCHEMA = 3


def expected_rss_unit():
    if sys.platform == "darwin":
        return "bytes (macOS getrusage RUSAGE_SELF)"
    if sys.platform.startswith("linux"):
        return "bytes (Linux getrusage RUSAGE_SELF, ru_maxrss KiB converted to bytes)"
    raise RuntimeError(f"unsupported platform: {sys.platform}")


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def load_json(path):
    def reject(value):
        raise ValueError(f"nonfinite JSON constant in {path}: {value}")
    return json.loads(Path(path).read_text(), parse_constant=reject)


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")
    temporary.replace(path)


def command(backend, case="S-add", representation="coef-binary", key_switch="AUTO"):
    wide = case in ("I63-add", "I63-mul", "F127-add", "F127-mul", "D25-d1", "D25-d2", "D25-d4")
    if backend == "pvac":
        return [str(BASE / ("build/pvac_wide" if wide else "build/pvac_bench"))]
    if backend in ("bfv", "bgv", "ckks"):
        executable = "build/openfhe_wide" if wide else "build/openfhe_bench"
        result = [str(BASE / executable), "--backend", backend]
        if wide:
            result += ["--representation", representation, "--key-switch", key_switch]
        return result
    if backend in ("tfhe16", "tfhe64"):
        return [str(BASE / "tfhe-harness/target/release/pvac-comparison-tfhe"), "--width", backend[4:]]
    if backend == "tfhe-wide":
        return [str(BASE / "tfhe-harness/target/release/pvac-comparison-tfhe"), "--width", "16", "--wide"]
    raise ValueError(backend)


def pvac_parameter_identity():
    parameters = load_json(BASE / "results/pvac-parameters.json")
    parameters.pop("kernel_selection_ms", None)
    return hashlib.sha256(canonical(parameters).encode()).hexdigest()


def manifest_identity():
    manifest = load_json(BASE / "results/harness-manifest.json")
    fixture_hash = sha256_file(BASE / "fixtures.json")
    if manifest.get("schema") != SCHEMA or manifest.get("fixtures_sha256") != fixture_hash:
        raise RuntimeError("manifest schema or fixture identity mismatch")
    if manifest.get("pvac_parameters_sha256") != pvac_parameter_identity():
        raise RuntimeError("PVAC parameter identity changed")
    import manifest as identity_manifest
    if identity_manifest.current_fingerprint() != manifest["combined_sha256"]:
        raise RuntimeError("stale harness manifest, regenerate it after any source or executable change")
    return manifest


def parameter_identity(result):
    backend = result["backend"]
    if backend == "pvac":
        return pvac_parameter_identity()
    if backend in ("bfv", "bgv", "ckks"):
        encoded = result.get("parameters_json")
        if encoded is None:
            reference = result.get("parameters_ref")
            if not reference:
                raise ValueError("missing OpenFHE parameter reference")
            encoded = load_json(BASE / reference)["parameters_json"]
        return hashlib.sha256(encoded.encode()).hexdigest()
    if backend.startswith("tfhe"):
        if result.get("parameter_alias") != "PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128":
            raise ValueError("unexpected TFHE parameter alias")
        return hashlib.sha256(canonical({"alias": result["parameter_alias"], "parameters": result["parameters"]}).encode()).hexdigest()
    raise ValueError(backend)


def canonical_fixture(fixture):
    if fixture.get("diagnostic"):
        return fixture
    source = "calibration-fixtures.json" if fixture.get("calibration") else "fixtures.json"
    for candidate in load_json(BASE / source):
        if candidate["case"] == fixture["case"] and candidate["fixture_id"] == fixture["fixture_id"]:
            if candidate != fixture:
                raise ValueError("fixture content differs from the canonical fixture")
            return candidate
    raise ValueError("unknown fixture")


def bind_record(result, fixture, profile, execution, schedule_path=None):
    manifest = manifest_identity()
    result["schema"] = SCHEMA
    result["harness_identity"] = manifest["combined_sha256"]
    result["execution_identity"] = manifest["execution_identity"]
    fixture_file = "calibration-fixtures.json" if fixture.get("calibration") else "fixtures.json"
    result["fixture_sha256"] = sha256_file(BASE / fixture_file)
    result["parameter_sha256"] = parameter_identity(result)
    result["schedule_sha256"] = sha256_file(schedule_path) if schedule_path else None
    result["profile"] = profile
    result["fixture"] = canonical_fixture(fixture)
    result["execution"] = dict(execution)
    if "process_peak_rss_bytes" not in result:
        raise ValueError("adapter exit RSS report is missing")
    result["execution"]["sampled_rss_kib"] = result["execution"].pop("peak_rss_kib")
    result["execution"]["peak_rss_kib"] = result["process_peak_rss_bytes"] // 1024
    result["execution"]["peak_rss_source"] = f"adapter getrusage at exit, {result['process_peak_rss_unit']}"
    result["validation"] = validate(result, fixture, check_identity=True)
    return result


def finite_number(value, name, nonnegative=True):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"nonnumeric value in {name}")
    if not math.isfinite(value):
        raise ValueError(f"nonfinite value in {name}")
    if nonnegative and value < 0:
        raise ValueError(f"negative value in {name}")


def validate(result, fixture, wrong=False, check_identity=False):
    fixture = canonical_fixture(fixture)
    case = fixture["case"]
    backend = result.get("backend")
    if backend not in BACKENDS or result.get("case") != case:
        raise ValueError("backend/case identity mismatch")
    expected = fixture["expected"].copy()
    if wrong:
        expected[0] = str(int(expected[0]) + 1) if isinstance(expected[0], str) else expected[0] + 1
    logical_outputs = result.get("logical_outputs")
    if isinstance(logical_outputs, bool) or not isinstance(logical_outputs, int) or logical_outputs != len(expected):
        raise ValueError("logical output shape mismatch")
    if "profile" in result and result["profile"] not in (1, 4):
        raise ValueError("invalid worker profile")
    if "requested_threads" in result and "profile" in result and result["requested_threads"] != result["profile"]:
        raise ValueError("requested/effective profile mismatch")
    if "execution" in result:
        finite_number(result["execution"].get("wall_seconds"), "execution wall_seconds")
        finite_number(result["execution"].get("peak_rss_kib"), "execution peak_rss_kib")
    batch_size = result.get("batch_size")
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size < 1:
        raise ValueError("invalid batch size")
    if batch_size != 1 and case not in ("S-add", "I63-add", "F127-add"):
        raise ValueError("micro-batching is only admitted for declared addition cases")
    for field in ("eval_ms", "decrypt_ms", "decrypt_batch_ms", "copy_reset_ms", "warmup_eval_ms", "warmup_decrypt_ms"):
        values = result.get(field)
        if not isinstance(values, list) or not values:
            raise ValueError(f"missing timing list {field}")
        for value in values:
            finite_number(value, field)
    for field in ("encryption_ms", "e2e_ms"):
        finite_number(result.get(field), field)
    for field in ("keygen_ms", "key_install_ms", "kernel_selection_ms"):
        if field in result and result[field] is not None:
            finite_number(result[field], field)
    for field in ("output_bytes", "batch_output_bytes", "output_ciphertext_bytes", "output_scales"):
        values = result.get(field, [])
        if not isinstance(values, list):
            raise ValueError(f"invalid list {field}")
        for value in values:
            finite_number(value, field)
    for field in ("input_bytes", "public_key_bytes", "server_key_bytes", "relinearization_key_bytes", "rotation_key_bytes"):
        if field in result and result[field] is not None:
            finite_number(result[field], field)
    batches = len(result["eval_ms"])
    if batches < 1:
        raise ValueError("no timed batches")
    for field in ("decrypt_ms", "decrypt_batch_ms", "copy_reset_ms", "output_bytes", "batch_output_bytes"):
        if len(result[field]) != batches:
            raise ValueError(f"batch count mismatch in {field}")
    repetitions = result.get("requested_repetitions")
    if repetitions is not None and (isinstance(repetitions, bool) or not isinstance(repetitions, int) or repetitions != batches):
        raise ValueError("repetition count mismatch")
    if result.get("requested_warmups") is not None:
        warmups = result["requested_warmups"]
        if isinstance(warmups, bool) or not isinstance(warmups, int) or warmups < 0:
            raise ValueError("invalid warmup count")
    else:
        warmups = None
    if "requested_repetitions" in result and "requested_warmups" in result:
        expected_values = result["requested_repetitions"] * batch_size * len(expected)
        recorded_count = result.get("expected_value_count")
        if isinstance(recorded_count, bool) or not isinstance(recorded_count, int) or recorded_count != expected_values:
            raise ValueError("expected value count mismatch")
    if result.get("fixture_count") is not None:
        count = result["fixture_count"]
        index = result.get("fixture_index")
        if not isinstance(count, int) or count < 1:
            raise ValueError("fixture index/count mismatch")
        if not isinstance(index, int) or index < 0 or index >= count:
            raise ValueError("invalid fixture index")
        if index == 0 and result.get("keygen_ms") is None:
            raise ValueError("setup missing for first fixture")
        if index > 0 and result.get("keygen_ms") is not None:
            raise ValueError("duplicated setup in key session")
    warmup_count = len(result["warmup_eval_ms"])
    if warmup_count < 1 or len(result["warmup_decrypt_ms"]) != warmup_count:
        raise ValueError("warmup timing count mismatch")
    if warmups is not None and warmup_count != warmups:
        raise ValueError("warmup count differs from request")
    expected_count = batches * batch_size * len(expected)
    worst_absolute = 0.0
    worst_relative = 0.0

    def check_values(actual, repetitions, label):
        nonlocal worst_absolute, worst_relative
        if len(actual) != repetitions * len(expected):
            raise ValueError(f"{label}: wrong output count {len(actual)}")
        for index, value in enumerate(actual):
            finite_number(value, f"{label} value", nonnegative=False)
            reference = expected[index % len(expected)]
            if backend == "ckks":
                error = abs(float(value) - reference)
                if not math.isfinite(error) or error > 1e-6 + 1e-8 * abs(reference):
                    raise ValueError(f"{label}: approximation mismatch at {index}")
                worst_absolute = max(worst_absolute, error)
                worst_relative = max(worst_relative, error / max(1, abs(reference)))
            elif not isinstance(value, int) or isinstance(value, bool) or value != reference:
                raise ValueError(f"{label}: exact mismatch at {index}: {value} != {reference}")

    def check_full(lo, hi, repetitions, label):
        if len(lo) != len(hi) or len(lo) != repetitions * len(expected):
            raise ValueError(f"{label}: wrong full-field output count")
        for index, (low, high) in enumerate(zip(lo, hi)):
            if (not isinstance(low, int) or isinstance(low, bool) or low < 0 or
                not isinstance(high, int) or isinstance(high, bool) or high < 0):
                raise ValueError(f"{label}: invalid field limb")
            actual = (high << 64) | low
            if actual != int(expected[index % len(expected)]):
                raise ValueError(f"{label}: full-field mismatch at {index}")

    def check_decimal(actual, repetitions, label, lifted=False):
        if len(actual) != repetitions * len(expected):
            raise ValueError(f"{label}: wrong decimal output count")
        for index, value in enumerate(actual):
            if not isinstance(value, str) or not value or (len(value) > 1 and value.startswith("0")) or not value.isdigit():
                raise ValueError(f"{label}: noncanonical decimal output")
            reference = fixture["lifted_expected"] if lifted else expected[index % len(expected)]
            if int(value) != int(reference):
                raise ValueError(f"{label}: exact decimal mismatch at {index}: {value} != {reference}")

    peak = result.get("process_peak_rss_bytes")
    if not isinstance(peak, int) or isinstance(peak, bool):
        raise ValueError("peak RSS must be an integer byte count")
    finite_number(peak, "process_peak_rss_bytes")
    if result.get("process_peak_rss_unit") != expected_rss_unit():
        raise ValueError("invalid peak RSS unit")
    raw = result.get("process_peak_rss_raw")
    if raw is None and sys.platform.startswith("linux"):
        raise ValueError("raw Linux ru_maxrss evidence is missing")
    if raw is not None:
        if not isinstance(raw, int) or isinstance(raw, bool) or raw <= 0:
            raise ValueError("invalid raw ru_maxrss value")
        raw_unit = result.get("process_peak_rss_raw_unit")
        multiplier = 1 if sys.platform == "darwin" and raw_unit == "bytes" else 1024 if sys.platform.startswith("linux") and raw_unit == "KiB" else None
        if multiplier is None or raw * multiplier != peak:
            raise ValueError("raw ru_maxrss unit or conversion mismatch")
    if result.get("process_peak_rss_source") != "adapter_exit":
        raise ValueError("peak RSS must be reported by the adapter at exit")
    key_bytes = sum(result.get(field, 0) or 0 for field in
                    ("public_key_bytes", "relinearization_key_bytes", "rotation_key_bytes", "server_key_bytes"))
    if peak < key_bytes:
        raise ValueError("reported peak RSS is smaller than serialized public/evaluation keys")
    if "rusage_evidence" in result:
        evidence = load_json(BASE / result["rusage_evidence"])
        if evidence.get("process_peak_rss_bytes") != peak:
            raise ValueError("peak RSS sidecar mismatch")
    if "execution" in result:
        if result["execution"].get("peak_rss_kib") != peak // 1024:
            raise ValueError("table RSS does not match the adapter exit report")
        if "sampled_rss_kib" in result["execution"]:
            finite_number(result["execution"]["sampled_rss_kib"], "sampled supervision RSS")
    if backend in ("bfv", "bgv", "ckks") and case == "D64":
        if result.get("rotation_key_count") != 6 or result.get("reduction_rotations") != 6:
            raise ValueError("D64 must use exactly six reduction rotations and keys")
    wide = fixture.get("wide", False)
    if wide and backend not in WIDE_BACKENDS:
        raise ValueError("backend is not admitted to the wide exact-integer panel")
    if backend == "pvac":
        if result.get("kernel") not in ("gf2_conv_pmull", "gf2_conv_clmul"):
            raise ValueError("PVAC runtime kernel rejected")
        if result.get("runtime_toeplitz_id") != result.get("runtime_toeplitz_id_at_completion"):
            raise ValueError("PVAC runtime dispatch changed")
        check_full(result["values_lo"], result["values_hi"], batches * batch_size, "measured")
        check_full(result["warmup_values_lo"], result["warmup_values_hi"], warmup_count, "warmup")
        check_full(result["e2e_values_lo"], result["e2e_values_hi"], 1, "e2e")
        if wide:
            check_decimal(result["values_decimal"], batches * batch_size, "measured decimal")
            check_decimal(result["warmup_values_decimal"], warmup_count, "warmup decimal")
            check_decimal(result["e2e_values_decimal"], 1, "e2e decimal")
    elif wide:
        check_decimal(result["values_decimal"], batches * batch_size, "measured decimal")
        check_decimal(result["warmup_values_decimal"], warmup_count, "warmup decimal")
        check_decimal(result["e2e_values_decimal"], 1, "e2e decimal")
        check_decimal(result["lift_decimal"], batches * batch_size, "measured lift", lifted=True)
        check_decimal(result["warmup_lift_decimal"], warmup_count, "warmup lift", lifted=True)
        check_decimal(result["e2e_lift_decimal"], 1, "e2e lift", lifted=True)
    else:
        check_values(result["values"], batches * batch_size, "measured")
        check_values(result["warmup_values"], warmup_count, "warmup")
        check_values(result["e2e_values"], 1, "e2e")
    if wide and backend in ("bfv", "bgv"):
        candidates = load_json(BASE / "wide-candidates.json")["cases"][case]
        selected = [candidate for candidate in candidates if candidate["representation"] == result.get("representation")]
        if len(selected) != 1:
            raise ValueError("wide OpenFHE representation is outside the frozen candidate grid")
        candidate = selected[0]
        if candidate["representation"].startswith("coef"):
            if (result.get("radix") != candidate["radix"] or
                    result.get("plaintext_modulus") != candidate["plaintext_modulus"] or
                    result.get("coefficients_per_input") != candidate["coefficients_per_input"]):
                raise ValueError("wide coefficient parameters differ from the candidate grid")
        elif result.get("crt_channels") != candidate["channels"] or result.get("crt_capacity") != candidate["capacity"]:
            raise ValueError("wide CRT parameters differ from the candidate grid")
        permitted_switches = candidate["key_switch_candidates"][backend]
        if result.get("key_switch_technique") not in permitted_switches:
            raise ValueError("key-switch technique is outside the candidate grid")
        if result.get("key_switch_requested") not in permitted_switches + ["AUTO"]:
            raise ValueError("requested key-switch technique is outside the candidate grid")
    if wide and backend == "tfhe-wide":
        containers = {
            "I63-add": ("FheUint64", "FheUint64"),
            "I63-mul": ("FheUint64", "FheUint128"),
            "F127-add": ("FheUint128", "FheUint128"),
            "F127-mul": ("FheUint128", "FheUint256"),
            "D25-d1": ("FheUint32", "FheUint128"),
            "D25-d2": ("FheUint32", "FheUint128"),
            "D25-d4": ("FheUint32", "FheUint128"),
        }
        if (result.get("input_container"), result.get("output_container")) != containers[case]:
            raise ValueError("TFHE wide containers differ from the declared widening contract")
    if backend.startswith("tfhe"):
        expected_ciphertexts = batches * batch_size * (len(expected) if case == "V64" else 1)
        if len(result["output_ciphertext_bytes"]) != expected_ciphertexts:
            raise ValueError("per-ciphertext diagnostic count mismatch")
        build_info = platform_support.tfhe_executable_info(BASE / "tfhe-harness/target/release/pvac-comparison-tfhe")
        for field in ("avx512_feature_compiled", "avx512_runtime_eligible"):
            if result.get(field) != build_info[field]:
                raise ValueError(f"TFHE record and executable differ on {field}")
    if check_identity:
        manifest = manifest_identity()
        if result.get("harness_identity") != manifest["combined_sha256"]:
            raise ValueError("stale harness identity")
        if result.get("execution_identity") != manifest["execution_identity"]:
            raise ValueError("stale executable identity")
        fixture_file = "calibration-fixtures.json" if result["fixture"].get("calibration") else "fixtures.json"
        if result.get("fixture_sha256") != sha256_file(BASE / fixture_file):
            raise ValueError("stale fixture identity")
        if result.get("parameter_sha256") != parameter_identity(result):
            raise ValueError("stale parameter identity")
        schedule = result.get("schedule_sha256")
        if schedule is not None and schedule != sha256_file(BASE / "results/pilot-schedule.json"):
            raise ValueError("stale schedule identity")
    return {"oracle": "PASS", "case": case, "fixture_id": fixture["fixture_id"],
            "worst_absolute_error": worst_absolute, "worst_relative_error": worst_relative,
            "timed_batches": batches, "batch_size": batch_size, "decrypted_values": expected_count}


def host_observation():
    return platform_support.observation()


def wait_for_quiet(timeout=1800, threshold=2.0, require_ac=True):
    platform_support.require_dedicated_linux()
    deadline = time.monotonic() + timeout
    observations = []
    while True:
        observation = host_observation()
        observations.append(observation)
        status = platform_support.quiet_status(observation, threshold, require_ac)
        if all(status[key] for key in ("load_ok", "ac_power", "thermal_ok", "swap_ok")):
            return observations
        if time.monotonic() >= deadline:
            raise RuntimeError(f"quiet gate failed: {status}")
        time.sleep(min(30, max(1, deadline - time.monotonic())))


def invoke(argv, stdin, log_stem, timeout=1800):
    log_stem = Path(log_stem)
    log_stem.parent.mkdir(parents=True, exist_ok=True)
    threads = "1"
    if "--threads" in argv:
        threads = argv[argv.index("--threads") + 1]
    if threads not in ("1", "4"):
        raise ValueError("invalid worker profile")
    env = os.environ.copy()
    env.update({"OMP_NUM_THREADS": threads, "OMP_THREAD_LIMIT": threads, "OMP_DYNAMIC": "FALSE",
                "OMP_MAX_ACTIVE_LEVELS": "1", "OPENBLAS_NUM_THREADS": "1",
                "VECLIB_MAXIMUM_THREADS": "1", "RAYON_NUM_THREADS": threads})
    start = time.monotonic()
    peak_rss = 0
    timed_out = False
    memory_exceeded = False
    affinity = None
    if sys.platform == "darwin":
        wrapped = ["caffeinate", "-i"] + argv
    elif sys.platform.startswith("linux"):
        affinity = platform_support.linux_affinity(int(threads))
        wrapped = affinity["taskset"] + argv
    else:
        raise RuntimeError(f"unsupported platform: {sys.platform}")
    with log_stem.with_suffix(".stdout").open("w") as stdout, log_stem.with_suffix(".stderr").open("w") as stderr:
        process = subprocess.Popen(wrapped, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                                   text=True, env=env, start_new_session=True)
        try:
            try:
                process.stdin.write(stdin)
                process.stdin.close()
            except BrokenPipeError:
                pass
            while process.poll() is None:
                rss = subprocess.run(["ps", "-o", "rss=", "-p", str(process.pid)],
                                     capture_output=True, text=True, timeout=5).stdout.strip()
                if rss:
                    peak_rss = max(peak_rss, int(rss))
                if peak_rss > MEMORY_LIMIT_KIB:
                    memory_exceeded = True
                    os.killpg(process.pid, signal.SIGTERM)
                if time.monotonic() - start > timeout:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGTERM)
                if timed_out or memory_exceeded:
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                    break
                time.sleep(0.35)
            process.wait()
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
    record = {
        "command": wrapped,
        "backend_command": argv,
        "returncode": process.returncode,
        "wall_seconds": time.monotonic() - start,
        "peak_rss_kib": peak_rss,
        "peak_rss_unit": f"KiB as reported by ps on {sys.platform}, sampled process RSS, not eval-only allocation",
        "affinity": affinity,
        "timed_out": timed_out,
        "memory_exceeded": memory_exceeded,
        "stdout": str(log_stem.with_suffix(".stdout")),
        "stderr": str(log_stem.with_suffix(".stderr")),
        "host": host_observation(),
    }
    write_json(log_stem.with_suffix(".execution.json"), record)
    if record["returncode"] or timed_out or memory_exceeded:
        error = log_stem.with_suffix(".stderr").read_text()
        raise RuntimeError(f"process failed ({record['returncode']}): {error[-2000:]}")
    return record


def one(args):
    fixture = load_json(args.fixture) if args.fixture else next(
        f for f in load_json(BASE / "fixtures.json")
        if f["case"] == args.case and f["fixture_id"] == args.fixture_id)
    fixture = canonical_fixture(fixture)
    argv = command(args.backend, args.case, getattr(args, "representation", "coef-binary"), getattr(args, "key_switch", "AUTO")) + [
                                    "--case", args.case, "--output", str(args.output) + ".tmp",
                                    "--repetitions", str(args.repetitions), "--warmups", str(args.warmups),
                                    "--batch", str(args.batch), "--threads", str(args.threads)]
    if args.key_output:
        argv += ["--key-output", str(args.key_output)]
    stdin = ",".join(map(str, fixture["x"])) + "\n" + ",".join(map(str, fixture["y"])) + "\n"
    try:
        execution = invoke(argv, stdin, args.output.with_suffix(""), args.timeout)
        rusage_path = Path(str(args.output) + ".tmp.rusage.json")
        rusage = load_json(rusage_path)
        final_rusage_path = args.output.with_suffix(".rusage.json").resolve()
        rusage_path.replace(final_rusage_path)
        raw = load_json(str(args.output) + ".tmp")
        raw.update(rusage)
        raw["rusage_evidence"] = str(final_rusage_path.relative_to(BASE))
        raw["requested_repetitions"] = args.repetitions
        raw["requested_warmups"] = args.warmups
        raw["validation"] = validate(raw, fixture, args.wrong_oracle)
        raw = bind_record(raw, fixture, args.threads, execution)
        raw["status"] = "PASS"
        write_json(args.output, raw)
        Path(str(args.output) + ".tmp").unlink(missing_ok=True)
        print(json.dumps({"status": "PASS", "output": str(args.output), "validation": raw["validation"]}, allow_nan=False))
    except Exception as error:
        rejected = Path(str(args.output) + ".tmp")
        if rejected.exists():
            rejected.rename(args.output.with_suffix(".rejected.json"))
        print(f"REJECTED: {error}", file=sys.stderr)
        return 1
    return 0


def selftest(backend):
    output = RESULTS / "smoke" / f"{backend}-selftest.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    case = "F127-mul" if backend == "tfhe-wide" else "S-add"
    default_timeout = 3600 if backend == "tfhe-wide" else 300
    timeout = int(os.environ.get("PVAC_WIDE_SELFTEST_TIMEOUT_SECONDS", str(default_timeout)))
    if timeout < 1:
        raise ValueError("PVAC_WIDE_SELFTEST_TIMEOUT_SECONDS must be positive")
    record = invoke(command(backend, case) + ["--selftest", "--output", str(output)], "",
                    RESULTS / "smoke" / "logs" / f"{backend}-selftest", timeout=timeout)
    result = load_json(output)
    rusage_path = Path(str(output) + ".rusage.json")
    if rusage_path.exists():
        result.update(load_json(rusage_path))
        result["rusage_evidence"] = str(rusage_path.relative_to(BASE))
    if result["selftest"] != "PASS":
        raise RuntimeError(f"selftest failed: {backend}")
    return {"backend": backend, "status": "PASS", "result": result, "execution": record}


def output_failure(backend):
    output = RESULTS / "smoke" / "missing" / "directory" / "cannot-write.json"
    start = time.monotonic()
    result = subprocess.run(command(backend) + ["--case", "S-add", "--output", str(output)],
                            input="1,2\n0,0\n", text=True, capture_output=True, timeout=10)
    if result.returncode == 0 or output.exists():
        raise RuntimeError(f"{backend}: output-open failure was accepted")
    return {"backend": backend, "status": "REJECTED_AS_REQUIRED", "returncode": result.returncode,
            "stderr": result.stderr, "wall_seconds": time.monotonic() - start}


def wrong_oracle():
    output = RESULTS / "smoke" / "wrong-oracle.json"
    args = argparse.Namespace(backend="pvac", case="S-add", fixture_id=1, fixture=None,
                              repetitions=1, warmups=1, batch=1, threads=1, output=output,
                              timeout=300, wrong_oracle=True, key_output=None)
    status = one(args)
    if status == 0:
        raise RuntimeError("known-wrong oracle was accepted")
    return {"status": "REJECTED_AS_REQUIRED", "exit_status": status,
            "evidence": str(output.with_suffix(".rejected.json"))}


def smoke(args):
    report = {"mode": "full-correctness-smoke", "started": utc(), "schema": SCHEMA,
              "venue": f"{sys.platform} build and correctness activity, not pilot timing",
              "selftests": [], "output_failures": [], "records": [], "cases": []}
    for backend in args.backends:
        report["selftests"].append(selftest(backend))
        report["output_failures"].append(output_failure(backend))
    report["wrong_oracle"] = wrong_oracle()
    selected = [f for f in load_json(BASE / "fixtures.json") if f["case"] in args.cases]
    for backend in args.backends:
        for fixture in selected:
            wide = fixture.get("wide", False)
            if wide and backend not in WIDE_BACKENDS:
                continue
            if not wide and backend not in SMALL_BACKENDS:
                continue
            if backend == "tfhe64" and fixture["case"] not in ("S-add", "S-mul"):
                continue
            output = RESULTS / "smoke" / backend / f"{fixture['case']}-{fixture['fixture_id']}.json"
            if output.exists():
                result = load_json(output)
                if result.get("status") != "PASS":
                    raise RuntimeError(f"invalid retained smoke record: {output}")
                validate(result, fixture, check_identity=True)
            else:
                status = one(argparse.Namespace(backend=backend, case=fixture["case"], fixture_id=fixture["fixture_id"],
                                                fixture=None, repetitions=1, warmups=1, batch=1, threads=1,
                                                output=output, timeout=args.timeout, wrong_oracle=False, key_output=None))
                if status:
                    report["status"] = "FAIL"
                    report["failed_cell"] = {"backend": backend, "case": fixture["case"], "fixture_id": fixture["fixture_id"]}
                    write_json(RESULTS / "smoke" / "summary.json", report)
                    raise RuntimeError(f"smoke cell failed: {backend} {fixture['case']} fixture={fixture['fixture_id']}")
            report["records"].append(str(output))
        report["cases"].append({"backend": backend, "status": "PASS"})
        write_json(RESULTS / "smoke" / "summary.json", report)
    report["finished"] = utc()
    report["status"] = "PASS"
    write_json(RESULTS / "smoke" / "summary.json", report)
    print(json.dumps({"status": "PASS", "records": len(report["records"]), "summary": str(RESULTS / "smoke/summary.json")}))


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    one_parser = sub.add_parser("one")
    one_parser.add_argument("--backend", choices=BACKENDS, required=True)
    one_parser.add_argument("--case", choices=CASES, required=True)
    one_parser.add_argument("--representation", choices=("coef-binary", "coef-radix", "crt30"), default="coef-binary")
    one_parser.add_argument("--key-switch", choices=("AUTO", "HYBRID", "BV"), default="AUTO")
    one_parser.add_argument("--fixture-id", type=int, default=0)
    one_parser.add_argument("--fixture", type=Path)
    one_parser.add_argument("--repetitions", type=int, default=1)
    one_parser.add_argument("--warmups", type=int, default=1)
    one_parser.add_argument("--batch", type=int, default=1)
    one_parser.add_argument("--threads", type=int, choices=(1, 4), default=1)
    one_parser.add_argument("--timeout", type=int, default=1800)
    one_parser.add_argument("--output", type=Path, required=True)
    one_parser.add_argument("--key-output", type=Path)
    one_parser.add_argument("--wrong-oracle", action="store_true")
    one_parser.set_defaults(function=one)
    smoke_parser = sub.add_parser("smoke")
    smoke_parser.add_argument("--backends", nargs="+", choices=BACKENDS, default=BACKENDS)
    smoke_parser.add_argument("--cases", nargs="+", choices=CASES, default=CASES)
    smoke_parser.add_argument("--timeout", type=int, default=1800)
    smoke_parser.set_defaults(function=smoke)
    args = parser.parse_args()
    raise SystemExit(args.function(args))


if __name__ == "__main__":
    main()
