# (PoC HFHE against everything) fhe benchmark suite

we use a testbed for full evaluation and comparison of all parameters and performance in our internal workflow, it is completely open source

we compare pvac_hfhe in its current proof of concept version which does not claim prod speed, it is provided as-is for hypothesis testing, bounty programs, and academic work. we compare an early research PoC against production optimized implementations from OpenFHE and tfhe-rs

this is a rerun of the whole suite. every scheme now runs the same programs on the same machine, every output is decrypted and checked, and tfhe is measured with real tfhe-rs integer operations instead of a gate count estimate. the suite also covers 63 bit integers and full 127 bit field elements

pvac_hfhe multiplies two ciphertexts in 2.63 ms, and the time stays the same up to full 127 bit field elements (2.72 ms). that is 6.10x faster than BFV, 2.78x faster than CKKS and within 1.25x of BGV, the fastest lattice scheme. on a ladder of 25 bit factors it is ahead of BGV at depth 1 and 2 (4.39x faster and 1.89x faster, BGV configured for depth 4). a fresh ciphertext is 43 KB, 6.04x to 18.1x smaller than a depth 1 rlwe ciphertext, and no evaluation keys are needed. against real tfhe-rs integer operations it is 712x faster on a 16 bit multiplication and 86600x faster on a 127 bit field multiplication

for this work we use one dedicated server with the following parameters:

- cpu: AMD EPYC 8024P, 8 cores / 16 threads, avx-512, bare metal
- ram: 64GB
- os: Ubuntu 24.04
- compiler: g++ 13.3.0 -O3 -march=native, rustc 1.99.1
- pvac_hfhe: research poc at 071b0e9 (unoptimized, single threaded)

how the run is set up, what every program is, the full tables and how to check the numbers: [METHOD.md](METHOD.md)

## schemes

| scheme | type | impl |
|--------|------|------|
| BFV | rlwe, exact int | OpenFHE 1.6.1 |
| BGV | rlwe, exact int | OpenFHE 1.6.1 |
| CKKS | rlwe, approximate | OpenFHE 1.6.1 |
| TFHE | radix integers, FheUint16 to FheUint256 | tfhe-rs 1.8.2 |
| PVAC_HFHE | lpn, exact field mod 2^127 - 1 | poc/research |

all times are medians in ms, one worker unless stated

---

### 0. PVAC_HFHE (PoC) vs TFHE-rs (real integer operations)

| op | PVAC_HFHE (PoC) | BGV | TFHE-rs 16 bit | TFHE-rs 64 bit | 16 bit vs pvac | 16 bit vs bgv | 64 bit vs pvac | 64 bit vs bgv |
|---|---|---|---|---|---|---|---|---|
| add | 0.0138 ms | 0.00751 ms | 268 ms | 1080 ms | 19400x | 35700x | 78300x | 144000x |
| mul | 2.63 ms | 2.11 ms | 1870 ms | 29200 ms | 712x | 887x | 11100x | 13800x |

four workers (pvac_hfhe is single threaded and does not change):

| op | PVAC_HFHE (PoC) | BGV | TFHE-rs 16 bit | TFHE-rs 64 bit | 16 bit vs pvac | 16 bit vs bgv | 64 bit vs pvac | 64 bit vs bgv |
|---|---|---|---|---|---|---|---|---|
| add | 0.0138 ms | 0.00756 ms | 107 ms | 463 ms | 7780x | 14200x | 33600x | 61300x |
| mul | 2.62 ms | 1.19 ms | 596 ms | 7980 ms | 227x | 503x | 3040x | 6710x |

these are measured tfhe-rs operations on the same machine, the 64 bit column is a 64 bit container holding the same small inputs. BGV is shown next to pvac_hfhe because native arithmetic in general is far ahead of bit level integers here. tfhe-rs bootstraps on the server inside these operations, which is what it pays for and what gives it unlimited depth and comparisons

## 1. scalar mul (ct * ct)

| scheme | ring | mul (ms) | vs pvac_hfhe |
|---|---|---|---|
| BGV | 8192 | 2.11 | 1.25x faster |
| PVAC_HFHE | - | 2.63 | 1.00x |
| CKKS | 16384 | 7.31 | 2.78x slower |
| BFV | 16384 | 16.1 | 6.10x slower |
| TFHE-rs 16 bit | - | 1870 | 712x slower |

---

## 2. scalar add (ct + ct)

| scheme | ring | add (ms) | vs pvac_hfhe |
|---|---|---|---|
| BGV | 4096 | 0.00751 | 1.84x faster |
| BFV | 8192 | 0.0133 | 1.04x faster |
| CKKS | 8192 | 0.0133 | 1.04x faster |
| PVAC_HFHE | - | 0.0138 | 1.00x |
| TFHE-rs 16 bit | - | 268 | 19400x slower |

---

## 3. wide values (63 bit integers, 127 bit field)

| program | PVAC_HFHE | BGV | BFV | TFHE-rs | bgv vs pvac | bfv vs pvac | tfhe vs pvac |
|---|---|---|---|---|---|---|---|
| 63 bit add | 0.0137 | 0.00759 | 0.0134 | 1080 | 1.81x faster | 1.02x faster | 78500x slower |
| 63 bit mul | 2.72 | 2.11 | 16.1 | 59300 | 1.29x faster | 5.91x slower | 21800x slower |
| field add | 0.0137 | 0.00757 | 0.0134 | 2180 | 1.81x faster | 1.02x faster | 159000x slower |
| field mul | 2.72 | 2.11 | 16.0 | 236000 | 1.29x faster | 5.89x slower | 86600x slower |
| ladder d1 | 2.74 | 12.0 | 24.7 | 15500 | 4.39x slower | 9.01x slower | 5650x slower |
| ladder d2 | 13.0 | 24.4 | 49.2 | 47900 | 1.89x slower | 3.80x slower | 3690x slower |
| ladder d4 | 143 | 41.2 | 98.7 | 147000 | 3.47x faster | 1.45x faster | 1030x slower |

pvac_hfhe multiplication on the sampled inputs, one worker: 2.63 ms (small), 2.72 ms (63 bit), 2.72 ms (127 bit field)

rlwe carries a wide value as digits in one ciphertext and the client puts the result together, pvac_hfhe keeps a field element in the ciphertext. the ladder multiplies d + 1 factors of 25 bits, with every rlwe context configured for depth 4. the tfhe-rs field multiplication is timed on one input pair, (p - 1) * (p - 1), in 6 key sessions over the two passes, and the factor uses pvac_hfhe on the same pair

---

## 4. ciphertext size

### fresh ct

| scheme | context | ct_size | vs pvac |
|---|---|---|---|
| PVAC_HFHE | any | 43 KB | 1.00x |
| BGV | depth 1 | 257 KB | 6.04x larger |
| BFV | depth 1 | 513 KB | 12.1x larger |
| CKKS | depth 1 | 769 KB | 18.1x larger |
| BGV | depth 4 | 1281 KB | 30.1x larger |
| BFV | depth 4 | 769 KB | 18.1x larger |
| CKKS | depth 4 | 1537 KB | 36.1x larger |
| TFHE-rs 16 bit | - | 129 KB | 3.03x larger |
| TFHE-rs 64 bit | - | 516 KB | 12.1x larger |

### PVAC_HFHE ct growth with depth

| depth | total time (ms) | ct_size | growth |
|---|---|---|---|
| d0 | - | 43 KB | 1.00x |
| d1 | 2.63 | 35 KB | 0.814x |
| d2 | 12.6 | 137 KB | 3.23x |
| d4 | 141 | 1371 KB | 32.2x |

rlwe output after the same chain at d1, d2, d4: BFV 513 KB / 513 KB / 769 KB, BGV 257 KB / 513 KB / 513 KB, CKKS 513 KB / 513 KB / 513 KB

---

## 5. depth

total time for x * y^d, every rlwe context sized for its own depth

| depth | PVAC_HFHE | BFV | BGV | CKKS | fastest |
|---|---|---|---|---|---|
| d1 | 2.63 | 16.1 | 2.11 | 7.30 | BGV 1.25x |
| d2 | 12.6 | 32.1 | 13.2 | 16.4 | PVAC 1.05x |
| d4 | 141 | 92.5 | 41.1 | 45.1 | BGV 3.44x |

---

## 6. vectors

### 64 independent products

| scheme | layout | time (ms) | vs pvac |
|---|---|---|---|
| PVAC_HFHE | one 64 slot ct | 4.69 | 1.00x |
| BGV | one packed ct | 2.11 | 2.22x faster |
| CKKS | one packed ct | 7.29 | 1.56x slower |
| BFV | one packed ct | 16.1 | 3.42x slower |
| TFHE-rs 16 bit | 64 integers | 121000 | 25800x slower |

### dot product of 64

| scheme | layout | time (ms) | vs pvac |
|---|---|---|---|
| PVAC_HFHE | 128 scalar cts | 172 | 1.00x |
| BGV | packed, 6 rotations | 14.1 | 12.2x faster |
| CKKS | packed, 6 rotations | 28.3 | 6.07x faster |
| BFV | packed, 6 rotations | 44.8 | 3.84x faster |
| TFHE-rs 16 bit | 128 integers | 126000 | 737x slower |

the first version gave rlwe one ciphertext per element. with packing rlwe wins the dot product

---

## 7. polynomial

f(x) = ((3x + 2)x + 5)x + 7, public coefficients

| scheme | time (ms) | vs pvac |
|---|---|---|
| PVAC_HFHE | 12.7 | 1.00x |
| BGV | 15.1 | 1.19x slower |
| CKKS | 16.9 | 1.33x slower |
| BFV | 35.5 | 2.80x slower |
| TFHE-rs 16 bit | 4910 | 388x slower |

---

## 8. four workers

| program | PVAC_HFHE | BFV | BGV | CKKS | TFHE-rs 16 bit |
|---|---|---|---|---|---|
| mul | 2.62 | 6.46 | 1.19 | 3.17 | 596 |
| dot64 | 171 | 19.8 | 8.25 | 13.9 | 39500 |
| poly | 12.7 | 15.2 | 7.53 | 7.03 | 1680 |
| chain d4 | 141 | 32.1 | 17.7 | 17.8 | 2380 |
| square d3 | 138 | 24.1 | 10.9 | 11.6 | 1780 |

---

## 9. keygen / encrypt / decrypt

| scheme | keygen (ms) | encrypt (ms) | decrypt (ms) |
|---|---|---|---|
| BGV | 11.1 | 2.16 | 0.464 |
| CKKS | 31.4 | 5.17 | 6.95 |
| BFV | 31.6 | 6.02 | 0.803 |
| PVAC_HFHE | 907 | 91.2 | 29.1 |
| TFHE-rs 16 bit | 2170 | 0.533 | 0.00412 |

for proof of concept this is ok, it happens because of the cumbersome approach to initialization, and keygen only needs to be called once from the wallet with the private key

---

## 10. key sizes

| scheme | public key | evaluation keys | median process peak |
|---|---|---|---|
| PVAC_HFHE | 16.4 MB | none | 53.4 MB |
| BGV | 0.251 MB | 0.751 MB relin | 39.0 MB |
| BFV | 0.501 MB | 2.00 MB relin | 39.0 MB |
| CKKS | 0.751 MB | 2.50 MB relin | 39.0 MB |
| TFHE-rs | - | 172 MB server key | 408 MB |

the pvac_hfhe key here is written uncompressed by the poc. the pvac library in octra-labs/lite_node at 8f785a9 writes the same key in 2.93 MB (extras/node_key_probe). it does not grow with depth and there are no evaluation keys

---

## mini-summary

### pvac_hfhe advantages

| metric | result |
|---|---|
| scalar mul vs bfv | 6.10x faster |
| scalar mul vs ckks | 2.78x faster |
| polynomial (depth 2) vs bfv / bgv / ckks | 2.80x faster / 1.19x faster / 1.33x faster |
| ct size (fresh) vs rlwe depth 1 scalar | 6.04x to 18.1x smaller |
| evaluation keys | none needed |
| tfhe-rs 16 bit mul, 1 worker / 4 workers | 712x faster / 227x faster |
| tfhe-rs 64 bit container mul, 1 worker / 4 workers | 11100x faster / 3040x faster |
| multiplication time across widths (small / 63 bit / 127 bit) | 2.63 ms / 2.72 ms / 2.72 ms |
| ladder d1 / d2 vs bgv in a depth 4 context | 4.39x faster / 1.89x faster |
| field mul vs bfv | 5.89x faster |
| field mul vs tfhe-rs on one input pair, 1 worker / 4 workers | 86600x faster / 23300x faster |

### pvac_hfhe limitations
(only valid for PoC HFHE)

| metric | limitation |
|---|---|
| scalar mul vs bgv | 1.25x slower |
| chain d4 / square d3 vs the best rlwe | 3.44x / 5.73x slower |
| ct growth at chain d4 | 32.2x the fresh size |
| packed dot product vs bfv / bgv / ckks | 3.84x slower / 12.2x slower / 6.07x slower |
| keygen vs rlwe | 28.7x to 81.6x slower |
| encrypt vs rlwe | 15.1x to 42.2x slower |
| end to end mul vs rlwe | 7.42x to 31.1x slower |
| threads | single threaded |
| refresh | only by decrypt + encrypt with the secret key, no public bootstrapping |
| field mul vs bgv | 1.29x slower |
| ladder d4 vs bgv / bfv | 3.47x slower / 1.45x slower |
| four workers, mul vs bgv | 2.21x slower |

## methodology

- same programs and same expected outputs for every scheme, one machine
- every measured output is decrypted and compared with an independent oracle
- timing: steady_clock, evaluation only unless stated
- stats: median over two full passes (second in reverse order), 3 fresh keys per pass
- sizes: real serialized bytes
- details in [METHOD.md](METHOD.md)

### caveats

1. pvac-hfhe is an early PoC with no optimizations and no threading. newer pvac code exists and is not measured here
2. openfhe and tfhe-rs are production optimized
3. the wide results are exact answers at the client, measured up to one multiplication on field elements and depth 4 on 25 bit factors
4. pvac security based on lpn (less studied than RLWE btw, but we are doing our best to close that gap)
5. tfhe-rs gives public bootstrapping and unlimited depth, this suite compares the cost of arithmetic and not that capability

---

## run

```bash
bash prepare.sh
RUN_MAIN=1 bash resume.sh
python3 verify_tables.py
```

the results of our run are in results/, see [METHOD.md](METHOD.md) for requirements and for what each file is
