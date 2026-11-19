#!/usr/bin/env python3
import argparse
import copy
import json
import math
from pathlib import Path
import subprocess

import fixtures
import harness
import wide_native_matrix

BASE = harness.BASE
P = fixtures.P127


def reference(case, x, y):
    if case == "I63-add":
        return x[0] + y[0]
    if case == "I63-mul":
        return x[0] * y[0]
    if case == "F127-add":
        return (x[0] + y[0]) % P
    if case == "F127-mul":
        return (x[0] * y[0]) % P
    depth = int(case.rsplit("d", 1)[1])
    result = 1
    for value in x[:depth + 1]:
        result *= value
    return result


def lifted(case, x, y):
    if case == "F127-add":
        return x[0] + y[0]
    if case == "F127-mul":
        return x[0] * y[0]
    return reference(case, x, y)


def digits(value, radix, count):
    result = []
    for _ in range(count):
        result.append(value % radix)
        value //= radix
    assert value == 0
    return result


def coefficient_reference(case, x, y, spec):
    radix = spec["radix"]
    count = spec["coefficients_per_input"]
    values = x[:int(case.rsplit("d", 1)[1]) + 1] if case.startswith("D25-d") else x + y
    inputs = [digits(value, radix, count) for value in values]
    if case.endswith("add"):
        return [a + b for a, b in zip(inputs[0], inputs[1])]
    result = inputs[0]
    for operand in inputs[1:]:
        product = [0] * (len(result) + len(operand) - 1)
        for i, a in enumerate(result):
            for j, b in enumerate(operand):
                product[i + j] += a * b
        result = product
    return result


def reconstruct_coefficients(coefficients, radix):
    return sum(value * radix ** index for index, value in enumerate(coefficients))


def crt_reference(values, moduli):
    product = math.prod(moduli)
    lifted = 0
    for value, modulus in zip(values, moduli):
        partial = product // modulus
        lifted += value * partial * pow(partial, -1, modulus)
    return lifted % product


def reject(label, function):
    try:
        function()
    except (AssertionError, ValueError, RuntimeError):
        return label
    raise AssertionError(f"negative control accepted: {label}")


def native_record(path):
    result = harness.load_json(path)
    sidecar = BASE / result["rusage_evidence"] if result.get("rusage_evidence") else Path(str(path) + ".rusage.json")
    if sidecar.exists():
        result.update(harness.load_json(sidecar))
    return result


def main():
    checks = []
    documents = fixtures.load_json(BASE / "fixtures.json") if hasattr(fixtures, "load_json") else harness.load_json(BASE / "fixtures.json")
    wide = [fixture for fixture in documents if fixture.get("wide")]
    grid = harness.load_json(BASE / "wide-candidates.json")
    for fixture in wide:
        case = fixture["case"]
        x = [int(value) for value in fixture["x"]]
        y = [int(value) for value in fixture["y"]]
        expected = reference(case, x, y)
        assert str(expected) == fixture["expected"][0]
        assert str(lifted(case, x, y)) == fixture["lifted_expected"]
        for spec in grid["cases"][case]:
            if spec["representation"].startswith("coef"):
                coefficients = coefficient_reference(case, x, y, spec)
                assert len(coefficients) - 1 <= spec["degree_bound"]
                assert max(coefficients) <= spec["coefficient_bound"]
                assert max(coefficients) < spec["plaintext_modulus"] / 2
                reconstructed = reconstruct_coefficients(coefficients, spec["radix"])
                assert reconstructed == lifted(case, x, y)
            else:
                moduli = spec["plaintext_moduli"]
                assert math.prod(moduli) > lifted(case, x, y)
                residues = [lifted(case, x, y) % modulus for modulus in moduli]
                assert crt_reference(residues, moduli) == lifted(case, x, y)
    checks.append("all-wide-fixtures-and-representations")

    pair = [(P - 1), (P - 1)]
    full = pair[0] * pair[1]
    assert full % P == 1
    assert (full & ((1 << 64) - 1)) % P != 1
    assert (full & ((1 << 128) - 1)) % P == 4
    assert (P - 1) ** 2 % P == 1
    assert (1 + (P - 1)) % P == 0
    checks.append("truncation-and-canonical-zero")

    binary = coefficient_reference("F127-mul", pair[:1], pair[1:], grid["cases"]["F127-mul"][0])
    dropped = binary[:-1]
    assert reconstruct_coefficients(dropped, 2) != full
    wrapped = [value % 64 for value in binary]
    assert reconstruct_coefficients(wrapped, 2) != full
    degree_wrap = [0] * 128
    for index, coefficient in enumerate(binary):
        degree_wrap[index % 128] += coefficient if (index // 128) % 2 == 0 else -coefficient
    assert reconstruct_coefficients(degree_wrap, 2) != full
    assert crt_reference([full % modulus for modulus in fixtures.CRT_PRIMES[:3]], fixtures.CRT_PRIMES[:3]) != full
    assert full - (1 << 53) != full - 1
    tampered = full + (1 << 54)
    assert tampered != full and tampered % P != full % P
    checks.append("dropped-limb-coefficient-degree-crt-and-bigint-controls")

    parser_dir = BASE / "results/input-controls"
    parser_dir.mkdir(parents=True, exist_ok=True)
    binary = BASE / "tfhe-harness/target/release/pvac-comparison-tfhe"
    for label, arguments, inputs in (("wide", ["--wide", "--case", "F127-add"], "1,,2\n1\n"),
                                      ("small", ["--case", "S-add"], "1,,2\n0\n")):
        completed = subprocess.run([str(binary), *arguments, "--output", str(parser_dir / f"{label}.json")],
                                   input=inputs, text=True, capture_output=True, timeout=10)
        if completed.returncode == 0 or "empty" not in completed.stderr:
            raise RuntimeError(f"Rust empty-token control was accepted: {label}")
    checks.append("rust-empty-token-rejection")

    fixture = next(item for item in wide if item["case"] == "F127-mul" and item["fixture_id"] == 2)
    wide_native_matrix.main()
    native_dir = BASE / "results/native-matrix"
    pvac_output = BASE / "results/wide-dev/pvac-f127.json"
    status = harness.one(argparse.Namespace(backend="pvac", case="F127-mul", fixture_id=2, fixture=None,
                                            repetitions=1, warmups=1, batch=1, threads=1, output=pvac_output,
                                            timeout=300, wrong_oracle=False, key_output=None, representation="coef-binary"))
    if status:
        raise RuntimeError("PVAC native boundary control failed")
    for name, path in (("pvac-f127", pvac_output),
                       ("bfv-coef-f127", native_dir / "bfv-F127-mul-coef-binary-HYBRID.json"),
                       ("bfv-crt-f127", native_dir / "bfv-F127-mul-crt30-HYBRID.json")):
        result = native_record(path)
        assert harness.validate(result, fixture)["oracle"] == "PASS"
        invalid = copy.deepcopy(result)
        invalid["values_decimal"][0] = str(int(invalid["values_decimal"][0]) + (1 << 54))
        reject(f"{name}-large-decimal-tamper", lambda: harness.validate(invalid, fixture))
        if name != "pvac-f127":
            invalid = copy.deepcopy(result)
            invalid["lift_decimal"][0] = str((full & ((1 << 128) - 1)))
            reject(f"{name}-truncated-lift", lambda: harness.validate(invalid, fixture))
        checks.append(f"native-validation-{name}")

    report = {"status": "PASS", "checks": checks, "wide_fixtures": len(wide), "native_records": 3,
              "scope": "independent integer and native adapter correctness, no benchmark timing"}
    harness.write_json(BASE / "results/wide-controls.json", report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
