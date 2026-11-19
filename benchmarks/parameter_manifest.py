#!/usr/bin/env python3
import json

import harness
from fixtures import SMALL_CASES, WIDE_CASES

BASE = harness.BASE


def main():
    pvac = harness.load_json(BASE / "results/pvac-parameters.json")
    if pvac.get("runtime_toeplitz_id") not in (1, 2):
        raise RuntimeError("PVAC runtime carry-less dispatch is required")
    openfhe = {}
    for backend in ("bfv", "bgv", "ckks"):
        openfhe[backend] = {}
        cases = SMALL_CASES if backend == "ckks" else SMALL_CASES + WIDE_CASES
        for case in cases:
            record = harness.load_json(BASE / "results/smoke" / backend / f"{case}-0.json")
            openfhe[backend][case] = {
                "source_evidence": f"results/smoke/{backend}/{case}-0.json",
                "parameters": json.loads(record["parameters_json"]),
                "parameter_sha256": harness.parameter_identity(record),
                "ring_dimension": record.get("ring_dimension"),
                "ring_dimensions": record.get("ring_dimensions"),
                "physical_slots": record.get("physical_slots"),
                "representation": record.get("representation"),
                "key_switch_requested": record.get("key_switch_requested"),
                "key_switch_technique": record.get("key_switch_technique"),
                "radix": record.get("radix"),
                "crt_channels": record.get("crt_channels"),
                "context_multiplicative_depth": record.get("context_multiplicative_depth"),
                "security_parameter": record["security_parameter"],
                "context_metadata_bytes": len(record["parameters_json"].encode()),
                "public_key_bytes": record["public_key_bytes"],
                "relinearization_key_bytes": record["relinearization_key_bytes"],
                "rotation_key_bytes": record["rotation_key_bytes"],
                "rotation_key_count": record.get("rotation_key_count"),
                "output_levels": record["output_levels"],
                "output_scales": record["output_scales"],
            }
    tfhe = {}
    for backend, case in (("tfhe16", "S-add"), ("tfhe64", "S-add"), ("tfhe-wide", "F127-mul")):
        record = harness.load_json(BASE / "results/smoke" / backend / f"{case}-0.json")
        tfhe[backend] = {
            "parameter_alias": record["parameter_alias"],
            "parameters": record["parameters"],
            "parameter_sha256": harness.parameter_identity(record),
            "integer_semantics": record["integer_semantics"],
            "input_container": record.get("input_container"),
            "output_container": record.get("output_container"),
            "avx512_feature_compiled": record.get("avx512_feature_compiled"),
            "avx512_runtime_eligible": record.get("avx512_runtime_eligible"),
            "encryption_key_model": record["encryption_key_model"],
            "server_key_bytes": record["server_key_bytes"],
            "server_key_breakdown": "combined server key, separate bootstrap/key-switch byte counts unavailable in this adapter",
            "computational_security": "vendor parameter family, no independent estimator validation in this harness",
            "per_pbs_failure": "vendor high-level default bound at most 2^-128, not measured by finite tests",
            "whole_program_failure_composition": "unavailable: high-level PBS/carry call counts are not instrumented, no numeric composition bound claimed",
        }
    identity = harness.manifest_identity()
    document = {
        "status": "PASS",
        "harness_identity": identity["combined_sha256"],
        "execution_identity": identity["execution_identity"],
        "security_claims_separate_from_performance": True,
        "pvac": {"parameters": pvac,
                 "parameter_sha256": harness.pvac_parameter_identity(),
                 "encryption_key_model": "secret_key",
                 "standalone_generator_modes": "scalar S=1 uses prf_R_noise via delta::Gen::scalar, multi-slot S>1 uses keyed XofShake (pvac.delta.slot) via delta::Gen::per_slot, this is not merely packing amortization and is not the lite_node engine",
                 "public_key_encoding": "experimental complete public-field encoding, no secret key serialized",
                 "ciphertext_encoding": "experimental PVCB0001 including every dynamic payload, not production wire",
                 "security_status": "concrete whole-construction security unestablished, no security-equivalence claim"},
        "openfhe": openfhe,
        "tfhe": tfhe,
        "ckks_wide_scope": "no reviewed exact-integer adapter included",
        "observed_zero_failures_is_not_a_probability_bound": True,
        "no_secret_or_client_keys_saved": True,
    }
    harness.write_json(BASE / "results/parameter-security.json", document)
    print(json.dumps({"status": "PASS", "output": str(BASE / "results/parameter-security.json"),
                      "pvac_kernel": pvac["kernel"], "runtime_toeplitz_id": pvac["runtime_toeplitz_id"],
                      "openfhe_contexts": sum(map(len, openfhe.values())),
                      "tfhe_parameter_sets": len(tfhe)}, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
