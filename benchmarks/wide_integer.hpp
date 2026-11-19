#pragma once

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

struct BigUInt {
    std::vector<uint32_t> w;

    BigUInt() = default;
    explicit BigUInt(uint64_t value) {
        if (value) w.push_back(static_cast<uint32_t>(value));
        if (value >> 32) w.push_back(static_cast<uint32_t>(value >> 32));
    }

    static BigUInt decimal(const std::string& text) {
        if (text.empty() || (text.size() > 1 && text.front() == '0') ||
            !std::all_of(text.begin(), text.end(), [](unsigned char c) { return std::isdigit(c); }))
            throw std::runtime_error("invalid canonical unsigned decimal");
        BigUInt value;
        for (char c : text) {
            value = value.mul_small(10);
            value.add_small(static_cast<uint32_t>(c - '0'));
        }
        return value;
    }

    bool zero() const { return w.empty(); }
    size_t bit_length() const {
        if (w.empty()) return 0;
        return 32 * (w.size() - 1) + (32 - __builtin_clz(w.back()));
    }
    int compare(const BigUInt& other) const {
        if (w.size() != other.w.size()) return w.size() < other.w.size() ? -1 : 1;
        for (size_t i = w.size(); i-- > 0;) {
            if (w[i] != other.w[i]) return w[i] < other.w[i] ? -1 : 1;
        }
        return 0;
    }
    void add_small(uint32_t value) {
        uint64_t carry = value;
        for (size_t i = 0; carry && i < w.size(); ++i) {
            uint64_t next = static_cast<uint64_t>(w[i]) + carry;
            w[i] = static_cast<uint32_t>(next);
            carry = next >> 32;
        }
        if (carry) w.push_back(static_cast<uint32_t>(carry));
    }
    BigUInt operator+(const BigUInt& other) const {
        BigUInt out;
        const size_t n = std::max(w.size(), other.w.size());
        out.w.resize(n);
        uint64_t carry = 0;
        for (size_t i = 0; i < n; ++i) {
            uint64_t next = carry;
            if (i < w.size()) next += w[i];
            if (i < other.w.size()) next += other.w[i];
            out.w[i] = static_cast<uint32_t>(next);
            carry = next >> 32;
        }
        if (carry) out.w.push_back(static_cast<uint32_t>(carry));
        return out;
    }
    BigUInt operator-(const BigUInt& other) const {
        if (compare(other) < 0) throw std::runtime_error("unsigned subtraction underflow");
        BigUInt out = *this;
        int64_t borrow = 0;
        for (size_t i = 0; i < out.w.size(); ++i) {
            int64_t next = static_cast<int64_t>(out.w[i]) - borrow - (i < other.w.size() ? other.w[i] : 0);
            out.w[i] = static_cast<uint32_t>(next);
            borrow = next < 0;
        }
        out.normalize();
        return out;
    }
    BigUInt operator*(const BigUInt& other) const {
        if (zero() || other.zero()) return BigUInt();
        BigUInt out;
        out.w.assign(w.size() + other.w.size(), 0);
        for (size_t i = 0; i < w.size(); ++i) {
            uint64_t carry = 0;
            for (size_t j = 0; j < other.w.size(); ++j) {
                uint64_t next = static_cast<uint64_t>(w[i]) * other.w[j] + out.w[i + j] + carry;
                out.w[i + j] = static_cast<uint32_t>(next);
                carry = next >> 32;
            }
            out.w[i + other.w.size()] = static_cast<uint32_t>(carry);
        }
        out.normalize();
        return out;
    }
    BigUInt mul_small(uint32_t value) const {
        if (zero() || value == 0) return BigUInt();
        BigUInt out;
        out.w.resize(w.size());
        uint64_t carry = 0;
        for (size_t i = 0; i < w.size(); ++i) {
            uint64_t next = static_cast<uint64_t>(w[i]) * value + carry;
            out.w[i] = static_cast<uint32_t>(next);
            carry = next >> 32;
        }
        if (carry) out.w.push_back(static_cast<uint32_t>(carry));
        out.normalize();
        return out;
    }
    uint32_t divmod_small(uint32_t divisor) {
        if (!divisor) throw std::runtime_error("division by zero");
        uint64_t remainder = 0;
        for (size_t i = w.size(); i-- > 0;) {
            uint64_t current = (remainder << 32) | w[i];
            w[i] = static_cast<uint32_t>(current / divisor);
            remainder = current % divisor;
        }
        normalize();
        return static_cast<uint32_t>(remainder);
    }
    BigUInt shl(size_t bits) const {
        if (zero()) return BigUInt();
        BigUInt out;
        const size_t whole = bits / 32, part = bits % 32;
        out.w.assign(whole, 0);
        uint64_t carry = 0;
        for (uint32_t value : w) {
            uint64_t next = (static_cast<uint64_t>(value) << part) | carry;
            out.w.push_back(static_cast<uint32_t>(next));
            carry = next >> 32;
        }
        if (carry) out.w.push_back(static_cast<uint32_t>(carry));
        return out;
    }
    BigUInt shr(size_t bits) const {
        const size_t whole = bits / 32, part = bits % 32;
        if (whole >= w.size()) return BigUInt();
        BigUInt out;
        out.w.assign(w.begin() + whole, w.end());
        if (part) {
            uint32_t carry = 0;
            for (size_t i = out.w.size(); i-- > 0;) {
                uint32_t current = out.w[i];
                out.w[i] = (current >> part) | carry;
                carry = current << (32 - part);
            }
        }
        out.normalize();
        return out;
    }
    BigUInt low_bits(size_t bits) const {
        BigUInt out = *this;
        const size_t whole = bits / 32, part = bits % 32;
        if (whole >= out.w.size()) return out;
        out.w.resize(whole + (part ? 1 : 0));
        if (part) out.w.back() &= (uint32_t{1} << part) - 1;
        out.normalize();
        return out;
    }
    uint64_t u64() const {
        if (w.size() > 2) throw std::runtime_error("integer does not fit u64");
        uint64_t value = w.empty() ? 0 : w[0];
        if (w.size() == 2) value |= static_cast<uint64_t>(w[1]) << 32;
        return value;
    }
    std::string str() const {
        if (zero()) return "0";
        BigUInt copy = *this;
        std::vector<uint32_t> groups;
        while (!copy.zero()) groups.push_back(copy.divmod_small(1000000000));
        std::ostringstream out;
        out << groups.back();
        for (size_t i = groups.size() - 1; i-- > 0;)
            out << std::setw(9) << std::setfill('0') << groups[i];
        return out.str();
    }
    void normalize() {
        while (!w.empty() && !w.back()) w.pop_back();
    }
};

inline BigUInt mersenne127_mod(BigUInt value) {
    const BigUInt p = BigUInt(uint64_t{0x7fffffffffffffff}).shl(64) + BigUInt(uint64_t{0xffffffffffffffff});
    while (value.bit_length() > 127) value = value.low_bits(127) + value.shr(127);
    if (value.compare(p) >= 0) value = value - p;
    return value;
}

inline BigUInt mersenne127_prime() {
    return BigUInt(uint64_t{0x7fffffffffffffff}).shl(64) + BigUInt(uint64_t{0xffffffffffffffff});
}

inline uint64_t modular_inverse(uint64_t value, uint64_t modulus) {
    int64_t old_r = static_cast<int64_t>(value), r = static_cast<int64_t>(modulus);
    int64_t old_s = 1, s = 0;
    while (r) {
        int64_t quotient = old_r / r;
        int64_t next = old_r - quotient * r;
        old_r = r;
        r = next;
        next = old_s - quotient * s;
        old_s = s;
        s = next;
    }
    if (old_r != 1) throw std::runtime_error("invalid modular inverse");
    old_s %= static_cast<int64_t>(modulus);
    if (old_s < 0) old_s += static_cast<int64_t>(modulus);
    return static_cast<uint64_t>(old_s);
}

inline BigUInt crt_reconstruct(const std::vector<uint64_t>& residues, const std::vector<uint64_t>& moduli) {
    if (residues.size() != moduli.size() || residues.empty()) throw std::runtime_error("invalid CRT input");
    BigUInt value;
    BigUInt product(1);
    for (size_t i = 0; i < moduli.size(); ++i) {
        if (moduli[i] < 2 || moduli[i] > UINT32_MAX || residues[i] >= moduli[i])
            throw std::runtime_error("invalid CRT residue");
        BigUInt reduced = value;
        uint64_t current = reduced.divmod_small(static_cast<uint32_t>(moduli[i]));
        BigUInt factor_value = product;
        uint64_t factor = factor_value.divmod_small(static_cast<uint32_t>(moduli[i]));
        uint64_t inverse = modular_inverse(factor, moduli[i]);
        uint64_t delta = residues[i] >= current ? residues[i] - current : residues[i] + moduli[i] - current;
        uint64_t coefficient = static_cast<uint64_t>((static_cast<unsigned __int128>(delta) * inverse) % moduli[i]);
        value = value + product.mul_small(static_cast<uint32_t>(coefficient));
        product = product.mul_small(static_cast<uint32_t>(moduli[i]));
    }
    return value;
}

inline void wide_integer_selftest() {
    const BigUInt p = mersenne127_prime();
    const BigUInt a = p - BigUInt(1);
    const BigUInt product = a * a;
    if (product.str() != "28948022309329048855892746252171976962636931432568264082937646787114745987076")
        throw std::runtime_error("wide multiplication selftest failed");
    if (mersenne127_mod(product).str() != "1") throw std::runtime_error("Mersenne reduction selftest failed");
    BigUInt truncated = product.low_bits(128);
    if (mersenne127_mod(truncated).str() != "4") throw std::runtime_error("truncation control lost its counterexample");
    if (BigUInt::decimal(product.str()).str() != product.str()) throw std::runtime_error("decimal roundtrip failed");
    const std::vector<uint64_t> moduli{1073741827, 1073741831, 1073741833, 1073741839, 1073741843};
    const BigUInt original = BigUInt::decimal("85070591730234615865843651857942052863");
    BigUInt capacity(1);
    std::vector<uint64_t> residues;
    for (uint64_t modulus : moduli) {
        BigUInt reduced = original;
        residues.push_back(reduced.divmod_small(static_cast<uint32_t>(modulus)));
        capacity = capacity.mul_small(static_cast<uint32_t>(modulus));
    }
    if (crt_reconstruct(residues, moduli).str() != original.str()) throw std::runtime_error("CRT roundtrip failed");
    if (capacity.compare(original) <= 0) throw std::runtime_error("CRT selftest needs sufficient capacity");
    for (uint64_t target = 0; target <= 1; ++target) {
        std::vector<uint64_t> small_residues(moduli.size(), target);
        auto reconstructed = crt_reconstruct(small_residues, moduli);
        if (reconstructed.compare(BigUInt(target)) != 0 || reconstructed.str() != std::to_string(target))
            throw std::runtime_error("small CRT result is not canonical");
        if (target == 0 && (!reconstructed.zero() || reconstructed.bit_length() != 0))
            throw std::runtime_error("CRT zero is not canonical");
        if (mersenne127_mod(reconstructed).compare(BigUInt(target)) != 0)
            throw std::runtime_error("small CRT reduction mismatch");
    }
}
