#include "pvac/pvac_c_api.h"
#include <cstdio>
#include <cstdint>
int main() {
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = i + 1;
    pvac_pubkey pk;
    pvac_seckey sk;
    pvac_keygen_from_seed(pvac_default_params(), seed, &pk, &sk);
    size_t n = 0;
    uint8_t* b = pvac_serialize_pubkey(pk, &n);
    std::printf("pubkey_bytes %zu\n", n);
    pvac_free_bytes(b);
    seed[0] = 9;
    pvac_cipher a = pvac_enc_value_seeded(pk, sk, 1234567, seed);
    seed[0] = 10;
    pvac_cipher c = pvac_enc_value_seeded(pk, sk, 89, seed);
    b = pvac_serialize_cipher(a, &n);
    std::printf("fresh_ct_bytes %zu\n", n);
    pvac_free_bytes(b);
    pvac_cipher s = pvac_ct_add(pk, a, c);
    b = pvac_serialize_cipher(s, &n);
    std::printf("add_ct_bytes %zu\n", n);
    pvac_free_bytes(b);
    seed[0] = 11;
    pvac_cipher m = pvac_ct_mul_seeded(pk, a, c, seed);
    b = pvac_serialize_cipher(m, &n);
    std::printf("mul_ct_bytes %zu\n", n);
    pvac_free_bytes(b);
    std::printf("dec_mul %llu dec_add %llu\n", (unsigned long long)pvac_dec_value(pk, sk, m),
                (unsigned long long)pvac_dec_value(pk, sk, s));
    return 0;
}
