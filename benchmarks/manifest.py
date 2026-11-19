#!/usr/bin/env python3
import json
from pathlib import Path
import platform
import subprocess
import sys

import harness
import platform_support

BASE = harness.BASE
HARNESS_FILES = [
    "fixtures.py", "fixtures.json", "calibration-fixtures.json", "wide-candidates.json", "harness.py", "schedule.py", "tables.py", "manifest.py", "controls.py",
    "platform_support.py", "process_rusage.hpp", "wide_integer.hpp", "pvac_bench.cpp", "pvac_wide.cpp", "pvac_parameters.cpp", "pvac_runtime.hpp",
    "openfhe_bench.cpp", "openfhe_wide.cpp", "tfhe-harness/Cargo.toml", "tfhe-harness/Cargo.lock", "tfhe-harness/src/main.rs", "tfhe-harness/src/wide.rs",
    "build-parameters.sh", "parameter_manifest.py", "build-openfhe.sh", "build-native.sh", "build-tfhe.sh",
    "build-diagnostics.sh", "build-tools-requirements.txt", "libomp-bottle.json", "openfhe_diagnostics.cpp",
    "diagnostics.py", "fetch-sources.sh", "fetch-libomp.py", "prepare.sh", "workloads.json", "resume.sh",
    "resume_d64.py", "progress.py", "export_samples.py", "verify_tables.py", "wide_controls.py", "wide_native_matrix.py", "representations.py",
    "representation_controls.py", "wide_batch_controls.py", "wide_integer_sanitizer.cpp", "build-sanitizer.sh", "two_pass_controls.py",
]


def run(args):
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout.strip()


def openfhe_build_dir():
    return BASE / ("build/openfhe-macos" if sys.platform == "darwin" else "build/openfhe-linux")


def openfhe_install_dir():
    return BASE / ("build/openfhe-install" if sys.platform == "darwin" else "build/openfhe-install-linux")


def cache_values():
    result = {}
    for line in (openfhe_build_dir() / "CMakeCache.txt").read_text().splitlines():
        if line.startswith(("CMAKE_BUILD_TYPE:", "CMAKE_CXX_FLAGS:", "CMAKE_C_FLAGS:",
                            "CMAKE_SHARED_LINKER_FLAGS:", "CMAKE_EXE_LINKER_FLAGS:",
                            "CMAKE_CXX_COMPILER:", "CMAKE_C_COMPILER:",
                            "NATIVE_SIZE:", "WITH_NATIVEOPT:", "WITH_OPENMP:", "WITH_HEXL:", "WITH_INTEL_HEXL:",
                            "OpenMP_CXX_FLAGS:", "OpenMP_CXX_LIB_NAMES:")):
            key, value = line.split("=", 1)
            result[key] = value
    return result


def linux_linked_libraries(binary):
    linked = run(["ldd", str(binary)])
    libraries = {}
    for line in linked.splitlines():
        fields = line.strip().split()
        candidate = None
        if "=>" in fields:
            index = fields.index("=>")
            if index + 1 < len(fields) and fields[index + 1].startswith("/"):
                candidate = fields[index + 1]
        elif fields and fields[0].startswith("/"):
            candidate = fields[0]
        if candidate is None:
            continue
        path = Path(candidate).resolve()
        if not path.is_file():
            raise FileNotFoundError(path)
        libraries[str(path)] = {"sha256": harness.sha256_file(path), "bytes": path.stat().st_size}
    return {"resolved_library_paths": sorted(libraries), "libraries": libraries}


def binary_record(relative):
    path = BASE / relative
    if not path.is_file():
        raise FileNotFoundError(path)
    if sys.platform == "darwin":
        return {"sha256": harness.sha256_file(path), "dynamic_libraries": run(["otool", "-L", str(path)]).splitlines()}
    if sys.platform.startswith("linux"):
        record = {"sha256": harness.sha256_file(path), "elf_dynamic": run(["readelf", "-d", str(path)]).splitlines()}
        record.update(linux_linked_libraries(path))
        return record
    raise RuntimeError(f"unsupported platform: {sys.platform}")


def toolchain():
    common = {
        "rustc": run(["rustc", "-vV"]),
        "cargo": run(["cargo", "--version"]),
        "machine": platform.machine(),
        "kernel": platform.release(),
    }
    if sys.platform == "darwin":
        common.update({
            "clang": run(["clang++", "--version"]),
            "cmake": run([str(BASE / ".build-tools/bin/cmake"), "--version"]),
            "macos": run(["sw_vers"]),
            "cpu": run(["sysctl", "-n", "machdep.cpu.brand_string"]),
            "memory_bytes": int(run(["sysctl", "-n", "hw.memsize"])),
        })
        return common
    common.update({
        "cxx": run(["g++", "--version"]),
        "cmake": run(["cmake", "--version"]),
        "os": run(["uname", "-a"]),
        "cpu": run(["lscpu"]),
        "memory_bytes": platform_support.meminfo().get("MemTotal"),
        "virtualization": platform_support.capture(["systemd-detect-virt"]),
        "cpu_topology": platform_support.cpu_topology(),
        "cpu_flags": platform_support.cpu_flags(),
    })
    return common


def tfhe_build_description():
    info = platform_support.tfhe_executable_info(BASE / "tfhe-harness/target/release/pvac-comparison-tfhe")
    return {
        "profile": "release, locked dependencies, default-features=false, integer, target-cpu=native",
        "avx512_feature_compiled": info["avx512_feature_compiled"],
        "avx512_runtime_eligible": info["avx512_runtime_eligible"],
        "avx512_host_eligible": info["avx512_host_eligible"],
        "provenance": "the executable's own --build-info report, checked against the current host",
        "runtime_scope": "feature and host ISA eligibility for the executed library dispatch, not an instruction count",
    }


def build_manifest():
    files = {}
    for relative in HARNESS_FILES:
        path = BASE / relative
        if not path.is_file():
            raise FileNotFoundError(path)
        files[relative] = {"bytes": path.stat().st_size, "sha256": harness.sha256_file(path)}
    source_identity = harness.hashlib.sha256(harness.canonical(files).encode()).hexdigest()
    binaries = {}
    execution_components = {"binaries": {}, "shared_libraries": {}}
    for relative in ("build/pvac_bench", "build/pvac_wide", "build/pvac_parameters", "build/openfhe_bench", "build/openfhe_wide",
                     "build/openfhe_diagnostics", "tfhe-harness/target/release/pvac-comparison-tfhe"):
        record = binary_record(relative)
        binaries[relative] = record
        execution_components["binaries"][relative] = record
    if sys.platform == "darwin":
        for name, relative in (("openfhe_core", "build/openfhe-install/lib/libOPENFHEcore.dylib"),
                               ("openfhe_pke", "build/openfhe-install/lib/libOPENFHEpke.dylib"),
                               ("libomp", "third-party/libomp/libomp/23.1.5/lib/libomp.dylib")):
            path = (BASE / relative).resolve()
            record = {"path": str(path), "sha256": harness.sha256_file(path)}
            execution_components["shared_libraries"][name] = record
            subprocess.run(["codesign", "--verify", str(path)], check=True, capture_output=True)
    else:
        inst = openfhe_install_dir()
        for name in ("OPENFHEcore", "OPENFHEpke"):
            path = inst / "lib" / f"lib{name}.so"
            if not path.is_file():
                raise FileNotFoundError(path)
            execution_components["shared_libraries"][name] = {
                "path": str(path.resolve()), "sha256": harness.sha256_file(path)
            }
    execution_identity = harness.hashlib.sha256(harness.canonical(execution_components).encode()).hexdigest()
    source_clean = subprocess.run(["git", "-C", str(BASE / "openfhe-git"), "diff", "--quiet", "HEAD"]).returncode == 0
    if not source_clean:
        raise RuntimeError("OpenFHE source differs from its pin")
    submodules = run(["git", "-C", str(BASE / "openfhe-git"), "submodule", "status", "--recursive"]).splitlines()
    if any(line.startswith(("+", "-", "U")) for line in submodules):
        raise RuntimeError("OpenFHE submodule identity mismatch")
    source = {
        "pvac": {"repository": "https://github.com/octra-labs/pvac_hfhe_cpp",
                 "commit": "071b0e909c119de815e284b347c4bd979cb59ef3",
                 "tree": "aa01515c7aa340c60ec903cc13ef74572b797186",
                 "include_export_sha256": harness.sha256_file(BASE / "sources/pvac-include.tar")},
        "openfhe": {"repository": "https://github.com/openfheorg/openfhe-development",
                    "commit": run(["git", "-C", str(BASE / "openfhe-git"), "rev-parse", "HEAD"]),
                    "tree": run(["git", "-C", str(BASE / "openfhe-git"), "rev-parse", "HEAD^{tree}"]),
                    "submodules": submodules, "clean": source_clean},
        "tfhe": {"repository": "https://github.com/zama-ai/tfhe-rs",
                 "commit": "e8f3926bb53d7eea95e8a7f581f60aae1c7aba16",
                 "archive_sha256": harness.sha256_file(BASE / "tfhe-rs.tar.gz")},
    }
    if source["openfhe"]["commit"] != "b59e1f291965f14fbee5172cd83a20f5b856204f":
        raise RuntimeError("wrong OpenFHE source identity")
    if source["pvac"]["include_export_sha256"] != "2125d49b24904ccfafb5c497dcd51bd6ffb27353ab9dd6abe1611bc71856ccaa":
        raise RuntimeError("PVAC include export differs from the reviewed pin")
    fixtures_sha256 = harness.sha256_file(BASE / "fixtures.json")
    workloads_sha256 = harness.sha256_file(BASE / "workloads.json")
    pvac_parameters_sha256 = harness.pvac_parameter_identity()
    tfhe_build = tfhe_build_description()
    combined = harness.hashlib.sha256(harness.canonical({
        "schema": harness.SCHEMA, "source_identity": source_identity, "execution_identity": execution_identity,
        "fixtures_sha256": fixtures_sha256, "workloads_sha256": workloads_sha256,
        "pvac_parameters_sha256": pvac_parameters_sha256, "sources": source,
        "openfhe_cmake": cache_values(), "tfhe_build": tfhe_build,
        "platform": sys.platform,
    }).encode()).hexdigest()
    pvac_parameters = harness.load_json(BASE / "results/pvac-parameters.json")
    if pvac_parameters.get("runtime_toeplitz_id") not in (1, 2):
        raise RuntimeError("PVAC parameter probe did not select an accelerated kernel")
    return {"schema": harness.SCHEMA, "harness_files": files, "source_identity": source_identity,
            "execution_identity": execution_identity, "combined_sha256": combined,
            "fixtures_sha256": fixtures_sha256, "workloads_sha256": workloads_sha256,
            "pvac_parameters_sha256": pvac_parameters_sha256,
            "sources": source, "toolchain": toolchain(), "binaries": binaries,
            "execution_components": execution_components, "openfhe_cmake": cache_values(),
            "openfhe_link_repair": "local libomp install_name and ad-hoc codesign on macOS, system OpenMP on Linux",
            "openfhe_acceleration": "stock native OpenFHE build without HEXL, AVX-512 host support or zmm operands elsewhere in the binary do not establish AVX-512 transform use",
            "tfhe_build": tfhe_build,
            "platform": sys.platform,
            "host_observation": platform_support.observation()}


def current_fingerprint():
    return build_manifest()["combined_sha256"]


def main():
    document = build_manifest()
    if sys.platform.startswith("linux"):
        inst = openfhe_install_dir()
        document["avx512_static_evidence"] = {
            "openfhe_core": platform_support.avx512_instruction_evidence(inst / "lib/libOPENFHEcore.so"),
            "openfhe_pke": platform_support.avx512_instruction_evidence(inst / "lib/libOPENFHEpke.so"),
            "tfhe": platform_support.avx512_instruction_evidence(BASE / "tfhe-harness/target/release/pvac-comparison-tfhe"),
        }
    harness.write_json(BASE / "results/harness-manifest.json", document)
    print(json.dumps({"manifest": str(BASE / "results/harness-manifest.json"),
                      "source_identity": document["source_identity"],
                      "execution_identity": document["execution_identity"],
                      "combined_sha256": document["combined_sha256"],
                      "harness_files": len(document["harness_files"]),
                      "binaries": len(document["binaries"])}, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
