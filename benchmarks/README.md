# (PoC HFHE against everything) fhe benchmark suite

we use a testbed for full evaluation and comparison of all parameters and performance in our internal workflow, it is completely open source

this is the second version of the suite. the first one compared native operations of each scheme on a cloud droplet and estimated the bit level numbers from gate counts. people pointed out (fairly) that this is not a like for like comparison, so we rebuilt it: every scheme now runs the same programs on the same machine, every output is decrypted and checked, and tfhe is measured with real tfhe-rs integer operations instead of an estimate

we compare pvac_hfhe in its current proof of concept version which does not claim prod speed, it is provided as-is for hypothesis testing, bounty programs, and academic work. we compare it against production optimized implementations from OpenFHE and tfhe-rs. the numbers describe the poc at the pinned commit and nothing newer

short version, one worker: one fresh pvac_hfhe multiplication takes 2.63 ms on small inputs, 2.72 ms on the sampled 63 bit inputs and 2.72 ms on the sampled 127 bit field elements. BGV is ahead on one multiplication at all three widths (1.25x faster, 1.29x faster and 1.29x faster), CKKS is 2.78x slower and BFV is 6.10x slower on small inputs. on the ladder of 25 bit factors pvac_hfhe is ahead of BGV at depth 1 and 2 (BGV is 4.39x slower and 1.89x slower there, in contexts configured for depth 4) and behind at depth 4. tfhe-rs integers are 712x slower on the 16 bit multiplication and 86600x slower on the field multiplication (the tfhe-rs field multiplication is timed on one input pair, (p - 1) * (p - 1), in 6 key sessions over the two passes, and the factor uses pvac_hfhe on the same pair). BGV is ahead of tfhe-rs by a similar factor, so that gap is about native arithmetic against bit level integers and not about pvac_hfhe. the wide results are exact answers at the client, see section 3. a fresh pvac_hfhe ciphertext is 1/6.0 to 1/18 the size of a depth 1 scalar rlwe ciphertext. it loses on depth, on packed vector work, on encryption and on keygen, and the ciphertext grows at greater multiplicative depth (the first multiplication gives a smaller ciphertext, the following ones grow it). all of that is in the tables below

the main tables come from one dedicated linux server:

- cpu: AMD EPYC 8024P, 8 cores / 16 threads, avx-512 and pclmulqdq, bare metal (no virtualization)
- ram: 64GB
- os: Ubuntu 24.04, kernel 6.8
- compiler: g++ 13.3.0, rustc 1.99.1
- flags: -O3 -march=native (pvac, openfhe adapter), release + target-cpu=native with the avx512 feature (tfhe-rs)
- placement: every measured process is pinned with taskset to distinct physical cores (one core for the 1 worker profile, four for the 4 worker profile), no smt siblings
- pvac_hfhe: research poc at 071b0e9, single threaded, clmul kernel

the first run of this version was made on an Apple M4 Pro laptop with the small programs only. its table is kept in section 11. numbers from the two machines are never divided by each other

## schemes

| scheme | type | impl | parameters |
|--------|------|------|------------|
| BFV | rlwe, exact int | OpenFHE 1.6.1 | HEStd_128_classic, library selected |
| BGV | rlwe, exact int | OpenFHE 1.6.1 | HEStd_128_classic, library selected |
| CKKS | rlwe, approximate | OpenFHE 1.6.1 | HEStd_128_classic, library selected |
| TFHE | radix integers, FheUint16 to FheUint256 | tfhe-rs 1.8.2 | PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 |
| PVAC_HFHE | lpn, exact field mod 2^127 - 1 | poc/research | default Params, security not established |

there is no "128-bit" label next to pvac_hfhe anymore. the lattice schemes run standard parameter sets chosen by their libraries, and we did not validate those estimates ourselves. OpenFHE is the stock build without hexl. the tfhe-rs parameter name carries a 2^-128 bound on the failure probability of one bootstrap, that is a correctness bound and not a security level or a bound for a whole program. pvac_hfhe has no finished security analysis, so this is a speed comparison and not an equal security comparison

## what is compared

there are two panels. in both every scheme computes the same thing and every output is decrypted and compared with an independent integer oracle

### small panel

inputs are small nonnegative integers and every intermediate value stays below 32768, so ordinary integer arithmetic agrees with the pvac field, with BFV/BGV mod 65537 and with a 16 bit tfhe integer. CKKS runs the same functions approximately and has to land within 1e-6 + 1e-8 * |expected|

| id | program | layout |
|----|---------|--------|
| add / mul | one ct + ct, one ct * ct | scalar |
| vec64 | 64 independent products | pvac: one 64 slot ct, rlwe: one packed ct, tfhe: 64 integers |
| dot64 | sum of 64 products, one encrypted result | pvac and tfhe: scalar cts, rlwe: packed + 6 rotations |
| poly | ((3x + 2)x + 5)x + 7, public coefficients | 2 ct * ct, 1 ct * const, 3 ct + const |
| chain d | x * y^d, both encrypted, d = 1, 2, 4 | d sequential ct * ct |
| square d | x^(2^d), d = 1, 2, 3 | d squarings (pvac uses ct_square) |

bfv and bgv contexts use the depth of the program. ckks also reserves one level for output accuracy and rescales after each ct * ct

### wide panel

exact arithmetic on wide values. CKKS is not in this panel

| id | program | inputs |
|----|---------|--------|
| 63 bit add / mul | x + y and x * y as integers | x, y below 2^63 |
| field add / mul | (x + y) mod p and (x * y) mod p, p = 2^127 - 1 | x, y below p |
| ladder d | product of d + 1 factors as an integer, d = 1, 2, 4 | factors below 2^25 |

the answer that is checked is the exact result at the client. pvac_hfhe works in the field mod p directly. BFV and BGV carry a wide value as digits in the coefficients of one ciphertext, the server adds or multiplies the polynomials, and the client puts the digits back together and reduces mod p. tfhe-rs widens the inputs before a multiplication so that the full product is kept, and the client reduces mod p. that client step is counted in the decrypt time of every scheme and not in the evaluation time

for every wide program and worker profile a short calibration run on separate inputs picked the BFV and BGV encoding with the lowest evaluation time out of binary digits, larger digits and 30 bit crt channels, and for BFV at depth also the key switching method. the digit encodings fit a wide value in one ciphertext, the crt encoding needs several. the tables use that choice. one worker:

| program | BGV encoding, key switching | BFV encoding, key switching | tfhe-rs containers |
|---|---|---|---|
| 63 bit add | radix 32 digits, HYBRID | radix 32 digits, HYBRID | FheUint64 |
| 63 bit mul | radix 32 digits, HYBRID | binary digits, HYBRID | FheUint64 widened to FheUint128 |
| field add | radix 32 digits, HYBRID | binary digits, HYBRID | FheUint128 |
| field mul | radix 32 digits, HYBRID | radix 32 digits, HYBRID | FheUint128 widened to FheUint256 |
| ladder d1 | radix 4 digits, HYBRID | radix 4 digits, BV | FheUint32 widened to FheUint128 |
| ladder d2 | binary digits, HYBRID | binary digits, BV | FheUint32 widened to FheUint128 |
| ladder d4 | radix 4 digits, HYBRID | radix 4 digits, BV | FheUint32 widened to FheUint128 |

four workers:

| program | BGV encoding, key switching | BFV encoding, key switching | tfhe-rs containers |
|---|---|---|---|
| 63 bit add | radix 32 digits, HYBRID | radix 32 digits, HYBRID | FheUint64 |
| 63 bit mul | radix 32 digits, HYBRID | binary digits, HYBRID | FheUint64 widened to FheUint128 |
| field add | radix 32 digits, HYBRID | binary digits, HYBRID | FheUint128 |
| field mul | radix 32 digits, HYBRID | binary digits, HYBRID | FheUint128 widened to FheUint256 |
| ladder d1 | radix 4 digits, HYBRID | binary digits, BV | FheUint32 widened to FheUint128 |
| ladder d2 | radix 4 digits, HYBRID | radix 4 digits, BV | FheUint32 widened to FheUint128 |
| ladder d4 | binary digits, HYBRID | radix 4 digits, BV | FheUint32 widened to FheUint128 |

the 30 bit crt encoding of the 63 bit and field multiplication could not be generated for BGV by the library (parameter generation fails), the other BGV encodings of those programs work

every rung of the ladder runs in fresh rlwe contexts configured for depth 4, also d1 and d2, the same way a deployment has to fix its depth in advance. pvac_hfhe pays per multiplication. for a single multiplication in a context sized for one multiplication see section 1, there BGV takes 2.11 ms against 12.0 ms here in the depth 4 context

### sampling

every number is a median over two full passes of the suite (the second pass in reverse order) with 3 fresh keys per pass, 540 key sessions per pass in 180 cells, 170 of them used in the tables (where two rlwe encodings of a wide program were run, only the one picked for evaluation time is shown). the timings of one cell share those keys, they are repeated measurements and not independent draws. additions faster than 0.1 ms are timed in batches of 1000 and reported as the median of the per call batch means, everything else is timed one call at a time. the evaluation medians of the two passes differ by at most 2.4% on any of the 170 cells, measured relative to their mean, and by 0.22% on the median cell. that sentence is about evaluation time only, setup, encryption, decryption and memory vary more between passes

correctness is checked on every input of every program for every scheme (6 per program, 8 for the field programs). timing uses 6 inputs, except for the slow tfhe cells below. a ratio between two schemes always uses the inputs that were timed for both of them

### timed inputs that are not all six, small panel

| scheme | program | workers | timed inputs | timings per pass |
|---|---|---|---|---|
| TFHE-rs 16 bit | V64 | 1 | input 0 | 3 |
| TFHE-rs 16 bit | D64 | 1 | input 0 | 3 |
| TFHE-rs 16 bit | P3 | 1 | inputs 0, 1 | 6 |
| TFHE-rs 16 bit | CH2 | 1 | inputs 0, 1 | 6 |
| TFHE-rs 16 bit | CH4 | 1 | inputs 0, 1 | 6 |
| TFHE-rs 16 bit | SQ2 | 1 | inputs 0, 1 | 6 |
| TFHE-rs 16 bit | SQ3 | 1 | inputs 0, 1 | 6 |
| TFHE-rs 16 bit | V64 | 4 | inputs 0, 1 | 6 |
| TFHE-rs 16 bit | D64 | 4 | inputs 0, 1 | 6 |
| TFHE-rs 16 bit | CH4 | 4 | inputs 0, 1 | 6 |
| TFHE-rs 64 bit | S-mul | 1 | inputs 0, 1 | 6 |
| TFHE-rs 64 bit | S-mul | 4 | inputs 0, 1 | 6 |

### timed inputs that are not all six, wide panel

| scheme | program | workers | timed inputs | timings per pass |
|---|---|---|---|---|
| TFHE-rs | 63 bit mul | 1 | inputs 2, 4 | 6 |
| TFHE-rs | field add | 1 | inputs 2, 6 | 6 |
| TFHE-rs | field mul | 1 | input 2 | 3 |
| TFHE-rs | ladder d1 | 1 | inputs 2, 4 | 6 |
| TFHE-rs | ladder d2 | 1 | inputs 2, 4 | 6 |
| TFHE-rs | ladder d4 | 1 | input 2 | 3 |
| TFHE-rs | 63 bit mul | 4 | inputs 2, 4 | 6 |
| TFHE-rs | field mul | 4 | input 2 | 3 |
| TFHE-rs | ladder d1 | 4 | inputs 2, 4 | 6 |
| TFHE-rs | ladder d2 | 4 | inputs 2, 4 | 6 |
| TFHE-rs | ladder d4 | 4 | inputs 2, 4 | 6 |

---

### 0. native arithmetic vs TFHE-rs (real integer operations)

one worker:

| op | PVAC_HFHE (PoC) | BGV | TFHE-rs 16 bit | TFHE-rs 64 bit | 16 bit vs pvac | 16 bit vs bgv | 64 bit vs pvac | 64 bit vs bgv |
|---|---|---|---|---|---|---|---|---|
| add | 0.0138 ms | 0.00751 ms | 268 ms | 1080 ms | 19400x | 35700x | 78300x | 144000x |
| mul | 2.63 ms | 2.11 ms | 1870 ms | 29200 ms | 712x | 887x | 11100x | 13800x |

four workers (pvac_hfhe is single threaded and does not change):

| op | PVAC_HFHE (PoC) | BGV | TFHE-rs 16 bit | TFHE-rs 64 bit | 16 bit vs pvac | 16 bit vs bgv | 64 bit vs pvac | 64 bit vs bgv |
|---|---|---|---|---|---|---|---|---|
| add | 0.0138 ms | 0.00756 ms | 107 ms | 463 ms | 7780x | 14200x | 33600x | 61300x |
| mul | 2.62 ms | 1.19 ms | 596 ms | 7980 ms | 227x | 503x | 3040x | 6710x |

BGV is in this table on purpose. every scheme that does arithmetic natively is far ahead of bit level integers on add and mul, this is not a pvac_hfhe property

the 64 bit column is a 64 bit container holding the same small inputs, it shows how tfhe cost grows with width. the wide panel below has real 63 bit and 127 bit inputs. the 64 bit multiplication is timed on inputs 0 and 1 only

tfhe-rs scales with workers and with the hardware. tfhe-rs publishes its own numbers for larger servers and gpus, we do not divide numbers from two different machines

the old "789000x" number is gone. it was nand latency times a gate count, not a measurement

tfhe-rs runs programmable bootstrapping on the server inside these arithmetic operations (for carries and digit products), with no key holder involved. that cost is part of the tfhe-rs timings in this suite. a bootstrap on its own was not measured, and a widening cast of a fresh unsigned ciphertext does not need one. this is what gives tfhe unlimited depth, comparisons and table lookups. pvac_hfhe and the rlwe schemes as measured here do not have that. this table compares the cost of one arithmetic operation, not the capability

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

addition is basically free for everything except tfhe

---

## 3. wide values

evaluation time in ms, one worker:

| program | PVAC_HFHE | BGV | BFV | TFHE-rs | bgv vs pvac | bfv vs pvac | tfhe vs pvac |
|---|---|---|---|---|---|---|---|
| 63 bit add | 0.0137 | 0.00759 | 0.0134 | 1080 | 1.81x faster | 1.02x faster | 78500x slower |
| 63 bit mul | 2.72 | 2.11 | 16.1 | 59300 | 1.29x faster | 5.91x slower | 21800x slower |
| field add | 0.0137 | 0.00757 | 0.0134 | 2180 | 1.81x faster | 1.02x faster | 159000x slower |
| field mul | 2.72 | 2.11 | 16.0 | 236000 | 1.29x faster | 5.89x slower | 86600x slower |
| ladder d1 | 2.74 | 12.0 | 24.7 | 15500 | 4.39x slower | 9.01x slower | 5650x slower |
| ladder d2 | 13.0 | 24.4 | 49.2 | 47900 | 1.89x slower | 3.80x slower | 3690x slower |
| ladder d4 | 143 | 41.2 | 98.7 | 147000 | 3.47x faster | 1.45x faster | 1030x slower |

four workers:

| program | PVAC_HFHE | BGV | BFV | TFHE-rs | bgv vs pvac | bfv vs pvac | tfhe vs pvac |
|---|---|---|---|---|---|---|---|
| 63 bit add | 0.0137 | 0.00764 | 0.0135 | 463 | 1.80x faster | 1.02x faster | 33800x slower |
| 63 bit mul | 2.73 | 1.18 | 6.39 | 16300 | 2.32x faster | 2.34x slower | 5970x slower |
| field add | 0.0138 | 0.00762 | 0.0134 | 946 | 1.81x faster | 1.03x faster | 68600x slower |
| field mul | 2.72 | 1.18 | 6.39 | 63200 | 2.31x faster | 2.35x slower | 23300x slower |
| ladder d1 | 2.72 | 4.66 | 8.18 | 4300 | 1.71x slower | 3.00x slower | 1580x slower |
| ladder d2 | 12.9 | 9.40 | 16.4 | 13100 | 1.38x faster | 1.27x slower | 1010x slower |
| ladder d4 | 143 | 18.0 | 32.9 | 40100 | 7.96x faster | 4.35x faster | 279x slower |

the tfhe-rs field multiplication is timed on one input pair, (p - 1) * (p - 1), in 6 key sessions over the two passes, and the factor uses pvac_hfhe on the same pair

pvac_hfhe multiplication on the sampled inputs, one worker: 2.63 ms (small), 2.72 ms (63 bit), 2.72 ms (127 bit field). BGV does not slow down with width either, because the digits of a wide value fit in one ciphertext. so on one wide multiplication the picture is the same as on a small one

what the rlwe columns do and do not show: they compute the integer result and the client reduces it. that gives the right field answer for any program made of additions and multiplications, as long as the digits do not overflow the plaintext modulus and the ring. every further multiplication makes the digits larger, so the parameters have to be chosen for the whole program in advance. pvac_hfhe keeps a reduced field element in every ciphertext. this suite measures up to depth 4 on 25 bit factors and one multiplication on full field elements, nothing deeper on wide values for any scheme

output ciphertext size:

| program | PVAC_HFHE | BGV | BFV | TFHE-rs |
|---|---|---|---|---|
| 63 bit mul | 35 KB | 257 KB | 513 KB | 1031 KB |
| field mul | 35 KB | 257 KB | 513 KB | 2063 KB |
| ladder d1 | 35 KB | 1281 KB | 1025 KB | 1031 KB |
| ladder d2 | 137 KB | 1025 KB | 1025 KB | 1031 KB |
| ladder d4 | 1371 KB | 513 KB | 1025 KB | 1031 KB |

end to end (encrypt inputs, evaluate, decrypt and reduce), ms, with the rlwe encodings that were picked for evaluation time:

| program | PVAC_HFHE | BGV | BFV | TFHE-rs |
|---|---|---|---|---|
| 63 bit mul | 214 | 8.20 | 31.6 | 59300 |
| field mul | 214 | 8.22 | 31.5 | 236000 |
| ladder d4 | 672 | 89.2 | 158 | 147000 |

---

## 4. ciphertext size

all sizes are real serialized bytes (binary), KB = 1024 bytes and MB = 1024 KB. the pvac serializer is a benchmark format that includes every dynamic payload, not a production wire format

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

### PVAC_HFHE ct growth with depth (chain)

| depth | total time (ms) | ct_size | growth |
|---|---|---|---|
| d0 | - | 43 KB | 1.00x |
| d1 | 2.63 | 35 KB | 0.814x |
| d2 | 12.6 | 137 KB | 3.23x |
| d4 | 141 | 1371 KB | 32.2x |

rlwe output after the same chain at d1, d2, d4: BFV 513 KB / 513 KB / 769 KB, BGV 257 KB / 513 KB / 513 KB, CKKS 513 KB / 513 KB / 513 KB

---

## 5. depth

total time for the whole program, not the last multiplication only

### chain (x * y^d)

| depth | PVAC_HFHE | BFV | BGV | CKKS | fastest |
|---|---|---|---|---|---|
| d1 | 2.63 | 16.1 | 2.11 | 7.30 | BGV 1.25x |
| d2 | 12.6 | 32.1 | 13.2 | 16.4 | PVAC 1.05x |
| d4 | 141 | 92.5 | 41.1 | 45.1 | BGV 3.44x |

### repeated squaring (x^(2^d))

| depth | PVAC_HFHE | BFV | BGV | CKKS | fastest |
|---|---|---|---|---|---|
| d1 | 1.96 | 16.1 | 2.11 | 7.30 | PVAC 1.08x |
| d2 | 11.2 | 32.1 | 13.0 | 16.3 | PVAC 1.16x |
| d3 | 139 | 69.4 | 24.3 | 29.5 | BGV 5.73x |

PoC: cost and size grow with depth, rlwe: close to linear in depth for these small circuits. the fastest column names the fastest of the four and how far pvac_hfhe is from it (or how far ahead). here every rlwe context is sized for its own depth, unlike the ladder in section 3

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

the pvac_hfhe 64 slot encryption uses a different noise generator from the scalar path, it takes 1930 ms to encrypt both inputs and 1860 ms to decrypt the result

### dot product of 64 (one encrypted sum)

| scheme | layout | time (ms) | vs pvac |
|---|---|---|---|
| PVAC_HFHE | 128 scalar cts | 172 | 1.00x |
| BGV | packed, 6 rotations | 14.1 | 12.2x faster |
| CKKS | packed, 6 rotations | 28.3 | 6.07x faster |
| BFV | packed, 6 rotations | 44.8 | 3.84x faster |
| TFHE-rs 16 bit | 128 integers | 126000 | 737x slower |

the first version of this suite gave rlwe one ciphertext per element here, which is not how anyone uses it. with packing rlwe wins the dot product clearly. the pvac_hfhe dot product result is 2211 KB

---

## 7. polynomial

f(x) = ((3x + 2)x + 5)x + 7, public coefficients, depth 2

| scheme | time (ms) | vs pvac |
|---|---|---|
| PVAC_HFHE | 12.7 | 1.00x |
| BGV | 15.1 | 1.19x slower |
| CKKS | 16.9 | 1.33x slower |
| BFV | 35.5 | 2.80x slower |
| TFHE-rs 16 bit | 4910 | 388x slower |

the first version encrypted the coefficients too (5 ct * ct). that variant is not in this table

---

## 8. four workers

pvac_hfhe is single threaded, the others use their own thread pools

| program | PVAC_HFHE | BFV | BGV | CKKS | TFHE-rs 16 bit |
|---|---|---|---|---|---|
| mul | 2.62 | 6.46 | 1.19 | 3.17 | 596 |
| dot64 | 171 | 19.8 | 8.25 | 13.9 | 39500 |
| poly | 12.7 | 15.2 | 7.53 | 7.03 | 1680 |
| chain d4 | 141 | 32.1 | 17.7 | 17.8 | 2380 |
| square d3 | 138 | 24.1 | 10.9 | 11.6 | 1780 |

---

## 9. keygen / encrypt / decrypt

keygen is the full setup for one multiplication (context and all required keys), the median of six setups. encrypt is half the time to encrypt the two inputs of one multiplication. decrypt is the time to decrypt the result of that multiplication, not a fresh ciphertext

| scheme | keygen (ms) | encrypt (ms) | decrypt (ms) |
|---|---|---|---|
| BGV | 11.1 | 2.16 | 0.464 |
| CKKS | 31.4 | 5.17 | 6.95 |
| BFV | 31.6 | 6.02 | 0.803 |
| PVAC_HFHE | 907 | 91.2 | 29.1 |
| TFHE-rs 16 bit | 2170 | 0.533 | 0.00412 |

pvac_hfhe keygen is 28.7x to 81.6x slower than rlwe and encrypt is 15.1x to 42.2x slower. pvac_hfhe encryption needs the secret key (it is a secret key scheme), OpenFHE encrypts with a public key, tfhe-rs with the client key

### end to end (encrypt inputs, evaluate, decrypt)

| program | PVAC_HFHE | BFV | BGV | CKKS | TFHE-rs 16 bit |
|---|---|---|---|---|---|
| mul | 214 | 28.9 | 6.89 | 24.7 | 1880 |
| poly | 148 | 42.3 | 21.2 | 29.9 | 4900 |
| chain d4 | 397 | 109 | 55.2 | 67.1 | 7560 |
| dot64 | 13700 | 57.6 | 18.9 | 45.9 | 126000 |

end to end pvac_hfhe is behind rlwe on everything, encryption dominates

---

## 10. key sizes and memory

| scheme | public key | evaluation keys | median process peak |
|---|---|---|---|
| PVAC_HFHE | 16.4 MB | none | 53.4 MB |
| BGV | 0.251 MB | 0.751 MB relin | 39.0 MB |
| BFV | 0.501 MB | 2.00 MB relin | 39.0 MB |
| CKKS | 0.751 MB | 2.50 MB relin | 39.0 MB |
| TFHE-rs | - | 172 MB server key | 408 MB |

sizes for the one multiplication context. the packed dot product adds rotation keys: BGV 4.51 MB, BFV 12.0 MB, CKKS 15.0 MB. memory is the median of the peak memory of the six processes that ran the multiplication, each including its own keygen, not evaluation only

the pvac_hfhe public key above is what the serializer of this poc writes, it stores the public matrix uncompressed. the pvac library inside octra-labs/lite_node at 8f785a9 writes a key of the same parameter set in 2.93 MB (3071533 bytes). we measured that separately, the program, the command and its output are in extras/node_key_probe, it is not produced by this suite. the pvac_hfhe key does not grow with depth and there are no evaluation keys. the rlwe keys can grow with the depth setting (some neighbouring settings give the same size) and every rotation adds a key

---

## 11. the laptop run

the small panel on an Apple M4 Pro laptop (macOS 27.2, Apple clang 21.0.0, -O3 -mcpu=native, pmull kernel for pvac, no cpu pinning), run of 2026-11-16, evaluation time in ms, one worker:

| program | PVAC_HFHE | BFV | BGV | CKKS | TFHE-rs 16 bit |
|---|---|---|---|---|---|
| add | 0.00409 | 0.00518 | 0.00275 | 0.00522 | 221 |
| mul | 1.23 | 7.38 | 0.811 | 3.25 | 1520 |
| vec64 | 1.79 | 7.38 | 0.814 | 3.26 | 98500 |
| dot64 | 84.0 | 20.5 | 5.79 | 13.6 | 103000 |
| poly | 5.85 | 16.5 | 7.00 | 7.37 | 4000 |
| chain d1 | 1.24 | 7.37 | 0.810 | 3.26 | 1530 |
| chain d2 | 5.90 | 14.8 | 6.07 | 7.25 | 3050 |
| chain d4 | 67.1 | 45.2 | 19.4 | 19.4 | 6090 |
| square d1 | 0.902 | 7.39 | 0.810 | 3.25 | 1520 |
| square d2 | 5.20 | 14.7 | 5.77 | 7.20 | 3030 |
| square d3 | 65.6 | 33.6 | 11.1 | 12.8 | 4550 |

on that machine a fresh pvac_hfhe ciphertext is 42 KB (the size of a fresh ciphertext varies a little from one encryption to the next) and one multiplication takes 1.23 ms. the order of the five schemes on scalar multiplication is the same on both machines. it differs on add, chain d4, square d1. do not divide a laptop number by a server number

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
(valid for PoC HFHE)

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
| public key | 16.4 MB |
| refresh | only by decrypt + encrypt with the secret key, no public bootstrapping |
| security | no finished analysis, no equal security claim |
| field mul vs bgv | 1.29x slower |
| ladder d4 vs bgv / bfv | 3.47x slower / 1.45x slower |
| four workers, mul vs bgv | 2.21x slower |

## methodology

- one machine per table, same programs, same expected outputs for every scheme
- every measured output is decrypted and compared with an independent integer oracle. pvac is compared on the full field element. the wide rlwe and tfhe outputs are compared both before and after the reduction at the client. a wrong output fails the run
- timing: steady_clock / Instant, evaluation only unless stated. end to end is measured directly, not summed from phases
- stats: median. per pass and cell 3 fresh keys x 6 inputs x 5 repetitions with one warmup. cells slower than 2 s use 3 keys x 2 inputs x 1 repetition, slower than 60 s use 3 keys x 1 input x 1 repetition
- two passes, second in reverse order with schemes interleaved, quiet machine gate before every session (load, thermal sensors, swap, and on linux no virtualization)
- sizes: real binary serialization for every scheme
- memory: peak of the whole process reported by the process itself

### caveats

1. pvac-hfhe is an early PoC with almost no optimizations and no threading. newer pvac code exists and is not measured here
2. openfhe and tfhe-rs are production optimized
3. the wide panel covers additions, one multiplication and a ladder up to depth 4. it does not measure deep programs on wide values, comparisons or any other bit level logic for any scheme
4. two machines, one table each. expect different ratios on other hardware
5. no equal security claim. pvac security is based on lpn plus a custom mask (less studied than RLWE, we are doing our best to close that gap)
6. pvac_hfhe is a secret key scheme. in this poc a ciphertext is refreshed by decrypt + encrypt with the secret key. tfhe-rs bootstraps on the server as part of its arithmetic and that cost is inside its timings, ckks can bootstrap. nothing here measures a refresh on its own for any scheme
7. no proof of correct evaluation or encryption is measured for any scheme

---

## the shipped results

results/tables.json and results/samples.json are our linux run of 2026-11-18 and 2026-11-19 on the server above, made with harness identity b9192ea6224bd51a19e788c9c4cd82ab6a4e4e03831c8f1892e3a940c86d9f5c (the identity covers the harness sources, the tool list that prepare.sh writes on that machine and the built binaries, the source part alone is e4cb2b832dd475362335cf94898a78c36c7f0c80cb433a7d64bb6751208a4233). since that run only punctuation changed in the harness (four output strings in fixtures.py, wide-candidates.json and two_pass_controls.py), no measured code path. results/published-representation-selection.json is a copy of the calibration that picked the BFV and BGV encodings, with the sha256 of the original file of the run. the harness does not read it. where the fastest encoding for evaluation and the fastest end to end differ, both were run and both are in the data, the tables above use the first one

results/macos/tables.json and results/macos/samples.json are the laptop run of 2026-11-16, made with harness identity de645cef684a0416a1531d4380574b39bff8b34da681279ab6ee6e57a2c0af7e, an earlier state of this harness without the wide panel

samples.json holds, for both passes, the evaluation, decryption, encryption, end to end and setup timings, the output sizes and the peak memory of every key session. `python3 verify_tables.py` rebuilds count, median, quartiles, interquartile range, minimum and maximum of those seven quantities for every cell and compares them with tables.json. it does not rebuild the other fields of tables.json. `python3 verify_tables.py --self-test` shows that it rejects nan values, duplicate rows or sessions, truncated samples and changed numbers. the verifier reads results/, to check the laptop data copy the two files from results/macos over them

## run

on linux you need a bare metal x86-64 machine with pclmulqdq, g++, cmake, cargo, git, curl, taskset, readelf, ldd and objdump. on macOS you need apple silicon, uv, cargo, clang and git

```bash
bash prepare.sh
RUN_MAIN=1 bash resume.sh
```

prepare.sh fetches the three pinned sources and builds everything. resume.sh does not build, it runs the correctness matrix, the calibration, the pilot, both passes, the tables, the sample export and the verification, and it continues after an interruption: a finished key session or correctness record is reused when it carries the current harness identity. a record left by another build stops the run, so remove the run directories under results/ after changing or rebuilding anything. a new run does not read the shipped files in results/, it overwrites tables.json and samples.json at its end. on the server above the whole thing took about 39 hours, most of it tfhe-rs. the timed stages refuse to start on a virtual machine

if systemd-inhibit is refused for your user, put a wrapper named systemd-inhibit earlier in PATH that takes the lock with sudo and runs the command as you

the pvac adapter is built from the pinned commit 071b0e9 that prepare.sh fetches, not from the include directory of this checkout. editing include/ does not change what is benchmarked
