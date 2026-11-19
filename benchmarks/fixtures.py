#!/usr/bin/env python3
import hashlib
import json
import math
from pathlib import Path
import random

BASE = Path(__file__).resolve().parent
SMALL_CASES = ["S-add", "S-mul", "V64", "D64", "P3", "CH1", "CH2", "CH4", "SQ1", "SQ2", "SQ3"]
WIDE_CASES = ["I63-add", "I63-mul", "F127-add", "F127-mul", "D25-d1", "D25-d2", "D25-d4"]
CASES = SMALL_CASES + WIDE_CASES
P127 = (1 << 127) - 1
CRT_PRIMES = [1073741827, 1073741831, 1073741833, 1073741839, 1073741843, 1073741857, 1073741891, 1073741909, 1073741939]


def is_wide_case(case):
    return case in WIDE_CASES


def vector(count, modulus, fixture):
    if fixture == 0:
        return [0] * count
    if fixture == 1:
        return [i % modulus for i in range(count)]
    if fixture == 2:
        return [modulus - 1] * count
    if fixture == 3:
        return [(i * 37 + 11) % modulus for i in range(count)]
    if fixture == 4:
        return [(i * i * 19 + 7) % modulus for i in range(count)]
    return [0 if i % 2 else modulus - 1 for i in range(count)]


def oracle(case, x, y):
    if case == "S-add":
        return [x[0] + y[0]]
    if case == "S-mul":
        return [x[0] * y[0]]
    if case == "V64":
        return [a * b for a, b in zip(x, y)]
    if case == "D64":
        return [sum(a * b for a, b in zip(x, y))]
    if case == "P3":
        return [((3 * x[0] + 2) * x[0] + 5) * x[0] + 7]
    if case.startswith("CH"):
        return [x[0] * y[0] ** int(case[2:])]
    if case.startswith("SQ"):
        return [x[0] ** (2 ** int(case[2:]))]
    if case == "I63-add":
        return [x[0] + y[0]]
    if case == "I63-mul":
        return [x[0] * y[0]]
    if case == "F127-add":
        return [(x[0] + y[0]) % P127]
    if case == "F127-mul":
        return [(x[0] * y[0]) % P127]
    if case.startswith("D25-d"):
        depth = int(case.rsplit("d", 1)[1])
        result = 1
        for value in x[:depth + 1]:
            result *= value
        return [result]
    raise ValueError(case)


def lifted_oracle(case, x, y):
    if case == "F127-add":
        return x[0] + y[0]
    if case == "F127-mul":
        return x[0] * y[0]
    return oracle(case, x, y)[0]


def small_fixtures():
    scalar = [(0, 0), (0, 1), (1, 127), (127, 127), (127, 1), (37, 91)]
    cubic = [0, 1, 2, 3, 5, 7]
    chain_x = [0, 1, 2, 3, 3, 2]
    chain_y = [0, 1, 2, 3, 2, 3]
    square = [0, 1, 2, 3, 0, 3]
    result = []
    for case in SMALL_CASES:
        for index in range(6):
            if case in ("S-add", "S-mul"):
                x, y = [scalar[index][0]], [scalar[index][1]]
            elif case in ("V64", "D64"):
                modulus = 128 if case == "V64" else 16
                x = vector(64, modulus, index)
                y = vector(64, modulus, (index + 2) % 6)
            elif case == "P3":
                x, y = [cubic[index]], []
            elif case.startswith("CH"):
                x, y = [chain_x[index]], [chain_y[index]]
            else:
                x, y = [square[index]], []
            expected = oracle(case, x, y)
            bound = 254 if case == "S-add" else 16129 if case in ("S-mul", "V64") else 14400 if case == "D64" else 1169 if case == "P3" else 243 if case.startswith("CH") else 6561
            assert all(0 <= v <= bound for v in expected)
            result.append({"case": case, "fixture_id": index, "x": x, "y": y, "expected": expected, "bound": bound})
    return result


def random_pair(seed, modulus):
    rng = random.Random(seed)
    return rng.randrange(modulus), rng.randrange(modulus)


def wide_pair_fixtures(case):
    if case.startswith("I63"):
        u = (1 << 63) - 1
        pairs = [(0, u), (1, u), (u, u), ((1 << 62) + 1, (1 << 62) - 1)]
        population = 1 << 63
    else:
        p = P127
        pairs = [(0, 0), (1, p - 1), (p - 1, p - 1), (1 << 126, 2), ((1 << 64) - 1, (1 << 64) + 1), (0, p - 1)]
        population = p
    pairs.extend(random_pair(f"pvac-wide-{case}-random-{index}", population) for index in range(2))
    return pairs


def wide_fixtures():
    result = []
    for case in WIDE_CASES:
        if case.startswith("D25"):
            u = (1 << 25) - 1
            vectors = [
                [0, 1, 2, 3, 4],
                [1, 1, 1, 1, 1],
                [u, u, u, u, u],
                [(1 << 24) + 1, (1 << 24) - 1, 1, u, 1 << 24],
            ]
            for seed_index in range(2):
                rng = random.Random(f"pvac-wide-D25-random-{seed_index}")
                vectors.append([rng.randrange(1 << 25) for _ in range(5)])
            inputs = [(values, []) for values in vectors]
        else:
            inputs = [((x,), (y,)) for x, y in wide_pair_fixtures(case)]
        for index, (x, y) in enumerate(inputs):
            expected = oracle(case, x, y)
            item = {
                "case": case,
                "fixture_id": index,
                "x": [str(value) for value in x],
                "y": [str(value) for value in y],
                "expected": [str(value) for value in expected],
                "lifted_expected": str(lifted_oracle(case, x, y)),
                "bound": str(max(expected)),
                "encoding": "canonical unsigned decimal strings",
                "wide": True,
            }
            result.append(item)
    return result


def input_bits(case):
    return 25 if case.startswith("D25") else 63 if case.startswith("I63") else 127


def factor_count(case):
    if not case.startswith("D25"):
        return 2
    return int(case.rsplit("d", 1)[1]) + 1


def coefficient_spec(case, radix, context=False):
    bits = input_bits(case)
    length = max(1, math.ceil(bits / math.log2(radix)))
    count = 5 if context and case.startswith("D25") else factor_count(case)
    addition = case.endswith("add")
    degree = (length - 1) if addition else count * (length - 1)
    coefficient = 2 * (radix - 1) if addition else length ** (count - 1) * (radix - 1) ** count
    return {"radix": radix, "coefficients_per_input": length, "degree_bound": degree, "coefficient_bound": coefficient}


def lifted_bound(case, context=False):
    if case == "I63-add":
        return 2 * ((1 << 63) - 1)
    if case == "I63-mul":
        return ((1 << 63) - 1) ** 2
    if case == "F127-add":
        return 2 * (P127 - 1)
    if case == "F127-mul":
        return (P127 - 1) ** 2
    count = 5 if context else factor_count(case)
    return ((1 << 25) - 1) ** count


def candidate_grid():
    cases = {}
    for case in WIDE_CASES:
        radix = 4 if case.startswith("D25") else 32
        representations = []
        for name, base, modulus in (("coef-binary", 2, 786433 if case.startswith("D25") else 65537),
                                    ("coef-radix", radix, 16777213 if case.startswith("D25") else 65537)):
            actual = coefficient_spec(case, base)
            context = coefficient_spec(case, base, context=True)
            representations.append({
                "representation": name,
                **actual,
                "plaintext_modulus": modulus,
                "context_multiplicative_depth": 4 if case.startswith("D25") else 0 if case.endswith("add") else 1,
                "num_large_digits": 0, "key_switch_candidates": {"bfv": ["HYBRID", "BV"] if case.startswith("D25") else ["HYBRID"], "bgv": ["HYBRID"]}, "default_key_switch": "AUTO",
                "context_degree_bound": context["degree_bound"],
                "context_coefficient_bound": context["coefficient_bound"],
                "positive_centered_decode_required": True,
                "native_admission": "pending",
            })
        bound = lifted_bound(case, context=True)
        product = 1
        moduli = []
        for prime in CRT_PRIMES:
            moduli.append(prime)
            product *= prime
            if product > bound:
                break
        representations.append({
            "representation": "crt30",
            "plaintext_moduli": moduli,
            "capacity": str(product),
            "lifted_bound": str(bound),
            "channels": len(moduli),
            "context_multiplicative_depth": 4 if case.startswith("D25") else 0 if case.endswith("add") else 1,
            "num_large_digits": 0, "key_switch_candidates": {"bfv": ["HYBRID", "BV"] if case.startswith("D25") else ["HYBRID"], "bgv": ["HYBRID"]}, "default_key_switch": "AUTO",
            "native_admission": "pending",
        })
        cases[case] = representations
    return {
        "schema": 1,
        "selection_metric": "median server evaluation over all six samples from both calibration fixtures, then median direct E2E over both fixtures, then representation and key-switch names, the E2E winner uses E2E first",
        "different_server_and_e2e_winners": "retain both as explicitly named frozen variants",
        "worker_budget": "one or four workers for the whole logical request, CRT channels run sequentially under the same process-wide OpenMP limit",
        "calibration_fixtures": "calibration-fixtures.json, disjoint seeds from final fixtures",
        "crt_primes": CRT_PRIMES,
        "cases": cases,
    }


def calibration_fixtures():
    result = []
    for case in WIDE_CASES:
        if case.startswith("D25"):
            inputs = []
            for index in range(2):
                rng = random.Random(f"pvac-wide-calibration-D25-{index}")
                inputs.append(([rng.randrange(1 << 25) for _ in range(5)], []))
        else:
            population = (1 << 63) if case.startswith("I63") else P127
            inputs = [((x,), (y,)) for x, y in (random_pair(f"pvac-wide-calibration-{case}-{index}", population) for index in range(2))]
        for index, (x, y) in enumerate(inputs):
            result.append({
                "case": case,
                "fixture_id": index,
                "x": [str(value) for value in x],
                "y": [str(value) for value in y],
                "expected": [str(value) for value in oracle(case, x, y)],
                "lifted_expected": str(lifted_oracle(case, x, y)),
                "wide": True,
                "calibration": True,
                "encoding": "canonical unsigned decimal strings",
            })
    return result


def write_document(name, value):
    encoded = json.dumps(value, indent=2, sort_keys=True) + "\n"
    (BASE / name).write_text(encoded)
    return {"file": name, "sha256": hashlib.sha256(encoded.encode()).hexdigest(), "records": len(value) if isinstance(value, list) else None}


def main():
    assert all(math.isqrt(prime) ** 2 != prime for prime in CRT_PRIMES)
    for prime in CRT_PRIMES:
        assert prime % 2 and all(prime % divisor for divisor in range(3, math.isqrt(prime) + 1, 2))
    documents = [
        write_document("fixtures.json", small_fixtures() + wide_fixtures()),
        write_document("calibration-fixtures.json", calibration_fixtures()),
        write_document("wide-candidates.json", candidate_grid()),
    ]
    print(json.dumps(documents, indent=2))


if __name__ == "__main__":
    main()
