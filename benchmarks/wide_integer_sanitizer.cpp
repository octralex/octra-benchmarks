#include "wide_integer.hpp"

#include <iostream>

int main() {
    wide_integer_selftest();
    const std::vector<uint64_t> moduli{1073741827, 1073741831, 1073741833, 1073741839, 1073741843};
    for (uint64_t target = 0; target <= 1; ++target) {
        std::vector<uint64_t> residues(moduli.size(), target);
        auto value = crt_reconstruct(residues, moduli);
        if (value.compare(BigUInt(target)) != 0) return 2;
        if (mersenne127_mod(value).compare(BigUInt(target)) != 0) return 3;
        std::cout << "{\"target\":" << target << ",\"limbs\":" << value.w.size()
                  << ",\"bit_length\":" << value.bit_length() << ",\"value\":\"" << value.str() << "\"}\n";
    }
    return 0;
}
