#include <pvac/pvac.hpp>
#include "pvac_runtime.hpp"
#include "process_rusage.hpp"

#ifndef PVAC_COMPILER_FLAGS
#error "PVAC_COMPILER_FLAGS must be supplied by the build script"
#endif

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <sys/resource.h>

using Clock = std::chrono::steady_clock;
using pvac::Cipher;
using pvac::PubKey;
using pvac::SecKey;

static double ms(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

struct Bytes {
    std::vector<uint8_t> data;
    size_t pos = 0;
    void u8(uint64_t x) { data.push_back(static_cast<uint8_t>(x)); }
    void u64(uint64_t x) {
        for (int i = 0; i < 8; ++i) data.push_back(static_cast<uint8_t>(x >> (8 * i)));
    }
    void raw(const uint8_t* p, size_t n) { data.insert(data.end(), p, p + n); }
    template <size_t N> void raw(const std::array<uint8_t, N>& a) { raw(a.data(), N); }
    uint64_t get64() {
        if (data.size() - pos < 8) throw std::runtime_error("truncated u64");
        uint64_t x = 0;
        for (int i = 0; i < 8; ++i) x |= static_cast<uint64_t>(data[pos++]) << (8 * i);
        return x;
    }
    uint8_t get8() {
        if (pos == data.size()) throw std::runtime_error("truncated u8");
        return data[pos++];
    }
    template <size_t N> void get(std::array<uint8_t, N>& a) {
        if (data.size() - pos < N) throw std::runtime_error("truncated array");
        std::copy_n(data.begin() + pos, N, a.begin());
        pos += N;
    }
    void count(size_t n, size_t cap) {
        if (n > cap || n > (data.size() - pos) / 8) throw std::runtime_error("invalid vector count");
    }
    void fp(const pvac::Fp& x) { u64(x.lo); u64(x.hi); }
    pvac::Fp fp() {
        uint64_t lo = get64(), hi = get64();
        if (hi > pvac::MASK63 || (hi == pvac::MASK63 && lo == UINT64_MAX))
            throw std::runtime_error("noncanonical field element");
        return pvac::Fp{lo, hi};
    }
    void bitvec(const pvac::BitVec& v) {
        u64(v.nbits); u64(v.w.size());
        for (uint64_t x : v.w) u64(x);
    }
    pvac::BitVec bitvec() {
        uint64_t n = get64(), words = get64();
        if (n == 0 || n > (1ULL << 30) || words != (n + 63) / 64) throw std::runtime_error("invalid bitvec");
        auto v = pvac::BitVec::make(n);
        for (auto& x : v.w) x = get64();
        if ((n & 63) && (v.w.back() >> (n & 63))) throw std::runtime_error("noncanonical bitvec");
        return v;
    }
};

static void params(Bytes& b, const pvac::Params& p) {
    for (int x : {p.B, p.m_bits, p.n_bits, p.h_col_wt, p.x_col_wt, p.err_wt,
                  p.lpn_n, p.lpn_t, p.lpn_tau_num, p.lpn_tau_den, p.recrypt_rounds}) {
        b.u64(static_cast<uint64_t>(static_cast<int64_t>(x)));
    }
    for (double x : {p.noise_entropy_bits, p.tuple2_fraction, p.depth_slope_bits,
                     p.recrypt_lo, p.recrypt_hi}) {
        uint64_t u;
        static_assert(sizeof u == sizeof x);
        std::memcpy(&u, &x, sizeof u);
        b.u64(u);
    }
    b.u64(p.edge_budget);
}

static pvac::Params read_params(Bytes& b) {
    pvac::Params p;
    std::vector<int*> ints = {&p.B, &p.m_bits, &p.n_bits, &p.h_col_wt, &p.x_col_wt, &p.err_wt,
                              &p.lpn_n, &p.lpn_t, &p.lpn_tau_num, &p.lpn_tau_den, &p.recrypt_rounds};
    for (int* x : ints) {
        int64_t v = static_cast<int64_t>(b.get64());
        if (v < std::numeric_limits<int>::min() || v > std::numeric_limits<int>::max())
            throw std::runtime_error("parameter overflow");
        *x = static_cast<int>(v);
    }
    for (double* x : {&p.noise_entropy_bits, &p.tuple2_fraction, &p.depth_slope_bits,
                      &p.recrypt_lo, &p.recrypt_hi}) {
        uint64_t u = b.get64();
        std::memcpy(x, &u, sizeof u);
    }
    p.edge_budget = b.get64();
    pvac::require_params(p);
    return p;
}

static std::vector<uint8_t> encode_pk(const PubKey& pk) {
    Bytes b;
    b.raw(reinterpret_cast<const uint8_t*>("PVPK0001"), 8);
    params(b, pk.prm);
    b.u64(pk.canon_tag);
    b.raw(pk.H_digest);
    b.u64(pk.H.size());
    for (const auto& v : pk.H) b.bitvec(v);
    b.u64(pk.ubk.perm.size()); b.u64(pk.ubk.inv.size());
    for (int x : pk.ubk.perm) b.u64(static_cast<uint32_t>(x));
    for (int x : pk.ubk.inv) b.u64(static_cast<uint32_t>(x));
    b.fp(pk.omega_B);
    b.u64(pk.powg_B.size());
    for (const auto& x : pk.powg_B) b.fp(x);
    return b.data;
}

static PubKey decode_pk(const std::vector<uint8_t>& bytes, const PubKey& expected) {
    Bytes b{bytes};
    if (bytes.size() < 8 || std::string(reinterpret_cast<const char*>(b.data.data()), 8) != "PVPK0001")
        throw std::runtime_error("bad public-key encoding magic");
    b.pos = 8;
    PubKey pk;
    pk.prm = read_params(b);
    pk.canon_tag = b.get64();
    b.get(pk.H_digest);
    if (pk.H_digest != expected.H_digest) throw std::runtime_error("wrong public-key context");
    size_t nh = b.get64(); b.count(nh, pk.prm.n_bits);
    for (size_t i = 0; i < nh; ++i) pk.H.push_back(b.bitvec());
    size_t np = b.get64(), ni = b.get64();
    if (np != static_cast<size_t>(pk.prm.m_bits) || ni != np) throw std::runtime_error("bad permutation");
    for (size_t i = 0; i < np; ++i) pk.ubk.perm.push_back(static_cast<int>(b.get64()));
    for (size_t i = 0; i < ni; ++i) pk.ubk.inv.push_back(static_cast<int>(b.get64()));
    pk.omega_B = b.fp();
    size_t ng = b.get64(); b.count(ng, pk.prm.B);
    for (size_t i = 0; i < ng; ++i) pk.powg_B.push_back(b.fp());
    if (b.pos != b.data.size() || encode_pk(pk) != bytes || !pvac::is_valid_pubkey_shape(pk))
        throw std::runtime_error("noncanonical public-key encoding");
    return pk;
}

static std::vector<uint8_t> encode_ct(const Cipher& c, const PubKey& pk) {
    if (!pvac::is_cipher_compatible_with_pubkey(pk, c)) throw std::runtime_error("invalid ciphertext");
    Bytes b;
    b.raw(reinterpret_cast<const uint8_t*>("PVCB0001"), 8);
    b.raw(pk.H_digest);
    b.u64(c.slots);
    b.u64(c.L.size()); b.u64(c.E.size()); b.u64(c.c0.size());
    for (const auto& l : c.L) {
        b.u8(static_cast<uint8_t>(l.rule));
        b.u64(l.seed.ztag); b.u64(l.seed.nonce.lo); b.u64(l.seed.nonce.hi);
        b.u64(l.pa); b.u64(l.pb); b.raw(l.R_com);
        b.u64(l.PC.size());
        for (const auto& x : l.PC) b.raw(x);
    }
    for (const auto& e : c.E) {
        b.u64(e.layer_id); b.u64(e.idx); b.u8(e.ch);
        b.u64(e.w.size());
        for (const auto& x : e.w) b.fp(x);
        b.bitvec(e.s);
    }
    for (const auto& x : c.c0) b.fp(x);
    return b.data;
}

static Cipher decode_ct(const std::vector<uint8_t>& bytes, const PubKey& pk) {
    Bytes b{bytes};
    if (bytes.size() < 48 || std::string(reinterpret_cast<const char*>(b.data.data()), 8) != "PVCB0001")
        throw std::runtime_error("bad ciphertext encoding");
    b.pos = 8;
    std::array<uint8_t, 32> digest;
    b.get(digest);
    if (digest != pk.H_digest) throw std::runtime_error("wrong public-key context");
    Cipher c;
    c.slots = b.get64();
    if (c.slots == 0 || c.slots > (1ULL << 24)) throw std::runtime_error("invalid slot count");
    size_t nl = b.get64(), ne = b.get64(), nc = b.get64();
    if (nl > 100000 || ne > pk.prm.edge_budget || nc > c.slots) throw std::runtime_error("invalid cipher counts");
    for (size_t i = 0; i < nl; ++i) {
        pvac::Layer l;
        uint8_t rule = b.get8();
        if (rule > 1) throw std::runtime_error("invalid layer rule");
        l.rule = static_cast<pvac::RRule>(rule);
        l.seed.ztag = b.get64(); l.seed.nonce.lo = b.get64(); l.seed.nonce.hi = b.get64();
        uint64_t pa = b.get64(), pb = b.get64();
        if (pa > UINT32_MAX || pb > UINT32_MAX) throw std::runtime_error("invalid parent");
        l.pa = pa; l.pb = pb; b.get(l.R_com);
        size_t npc = b.get64();
        if (npc != 0 && npc != c.slots) throw std::runtime_error("invalid PC shape");
        for (size_t j = 0; j < npc; ++j) { std::array<uint8_t, 32> x; b.get(x); l.PC.push_back(x); }
        c.L.push_back(std::move(l));
    }
    for (size_t i = 0; i < ne; ++i) {
        pvac::Edge e;
        uint64_t lid = b.get64(), idx = b.get64();
        if (lid >= nl || lid > UINT32_MAX || idx >= pk.powg_B.size() || idx > UINT16_MAX)
            throw std::runtime_error("invalid edge reference");
        e.layer_id = lid; e.idx = idx; e.ch = b.get8();
        if (e.ch > 1) throw std::runtime_error("invalid edge sign");
        size_t nw = b.get64();
        if (nw != c.slots) throw std::runtime_error("invalid edge weights");
        for (size_t j = 0; j < nw; ++j) e.w.push_back(b.fp());
        e.s = b.bitvec();
        c.E.push_back(std::move(e));
    }
    for (size_t i = 0; i < nc; ++i) c.c0.push_back(b.fp());
    if (b.pos != bytes.size() || encode_ct(c, pk) != bytes) throw std::runtime_error("noncanonical ciphertext");
    return c;
}

static std::vector<uint64_t> read_vec() {
    std::string line;
    if (!std::getline(std::cin, line)) throw std::runtime_error("missing input vector");
    std::stringstream ss(line);
    std::vector<uint64_t> v;
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (item.empty()) throw std::runtime_error("empty input item");
        v.push_back(std::stoull(item));
    }
    return v;
}

static int depth_of(const std::string& name) {
    if (name.rfind("CH", 0) == 0 || name.rfind("SQ", 0) == 0) return std::stoi(name.substr(2));
    return 0;
}

static Cipher evaluate(const PubKey& pk, const std::string& name, const std::vector<Cipher>& in) {
    using namespace pvac;
    if (name == "S-add") return ct_add(pk, in[0], in[1]);
    if (name == "S-mul" || name == "V64") return ct_mul(pk, in[0], in[1]);
    if (name == "D64") {
        Cipher acc = ct_mul(pk, in[0], in[1]);
        for (size_t i = 1; i < 64; ++i) acc = ct_add(pk, acc, ct_mul(pk, in[2 * i], in[2 * i + 1]));
        return acc;
    }
    if (name == "P3") {
        Cipher t = ct_add_const(pk, ct_mul_const(pk, in[0], uint64_t{3}), uint64_t{2});
        t = ct_add_const(pk, ct_mul(pk, t, in[0]), uint64_t{5});
        return ct_add_const(pk, ct_mul(pk, t, in[0]), uint64_t{7});
    }
    if (name.rfind("CH", 0) == 0) {
        Cipher acc = in[0];
        for (int d = 0; d < depth_of(name); ++d) acc = ct_mul(pk, acc, in[1]);
        return acc;
    }
    if (name.rfind("SQ", 0) == 0) {
        Cipher acc = in[0];
        for (int d = 0; d < depth_of(name); ++d) acc = ct_square(pk, acc);
        return acc;
    }
    throw std::runtime_error("unknown case");
}

static void values(const PubKey& pk, const SecKey& sk, const Cipher& c,
                   std::vector<uint64_t>& lo, std::vector<uint64_t>& hi) {
    for (auto x : pvac::dec_values(pk, sk, c)) { lo.push_back(x.lo); hi.push_back(x.hi); }
}

static std::string nums(const std::vector<double>& v) {
    std::ostringstream s;
    s << std::setprecision(17) << "[";
    for (size_t i = 0; i < v.size(); ++i) { if (i) s << ','; s << v[i]; }
    return s.str() + "]";
}

static std::string nums(const std::vector<uint64_t>& v) {
    std::ostringstream s;
    s << "[";
    for (size_t i = 0; i < v.size(); ++i) { if (i) s << ','; s << v[i]; }
    return s.str() + "]";
}

static std::pair<std::vector<Cipher>, double> encrypt(const PubKey& pk, const SecKey& sk,
        const std::string& name, const std::vector<uint64_t>& x, const std::vector<uint64_t>& y) {
    auto t = Clock::now();
    std::vector<Cipher> in;
    if (name == "V64") {
        in.push_back(pvac::enc_values(pk, sk, x)); in.push_back(pvac::enc_values(pk, sk, y));
    } else if (name == "D64") {
        for (size_t i = 0; i < 64; ++i) {
            in.push_back(pvac::enc_value(pk, sk, x[i])); in.push_back(pvac::enc_value(pk, sk, y[i]));
        }
    } else {
        in.push_back(pvac::enc_value(pk, sk, x[0]));
        if (name == "S-add" || name == "S-mul" || name.rfind("CH", 0) == 0)
            in.push_back(pvac::enc_value(pk, sk, y[0]));
    }
    return {std::move(in), ms(t, Clock::now())};
}

static int selftest(const std::string& output) {
    std::ofstream out(output);
    if (!out) throw std::runtime_error("cannot open output file");
    auto runtime = checked_pvac_kernel();
    pvac::Params p;
    PubKey pk, other;
    SecKey sk, osk;
    pvac::keygen(p, pk, sk);
    pvac::keygen(p, other, osk);
    auto c = pvac::ct_mul(pk, pvac::enc_value(pk, sk, 7), pvac::enc_value(pk, sk, 6));
    auto enc = encode_ct(c, pk);
    auto round = decode_ct(enc, pk);
    auto value = pvac::dec_value(pk, sk, round);
    if (value.lo != 42 || value.hi != 0) throw std::runtime_error("roundtrip mismatch");
    auto pkenc = encode_pk(pk);
    auto decoded_pk = decode_pk(pkenc, pk);
    if (encode_pk(decoded_pk) != pkenc) throw std::runtime_error("public-key roundtrip mismatch");
    value = pvac::dec_value(decoded_pk, sk, round);
    if (value.lo != 42 || value.hi != 0) throw std::runtime_error("functional public-key roundtrip failed");
    pvac::Fp full_plain{123456789ULL, 12345ULL};
    auto full = pvac::enc_fp_wrapped_depth(pk, sk, full_plain, 0);
    auto full_round = decode_ct(encode_ct(full, pk), pk);
    value = pvac::dec_value(pk, sk, full_round);
    if (value.lo != full_plain.lo || value.hi != full_plain.hi) throw std::runtime_error("full-field roundtrip failed");
    auto packed = pvac::ct_square(pk, pvac::ct_square(pk, pvac::enc_values(pk, sk, {1, 2, 3})));
    auto packed_round = decode_ct(encode_ct(packed, pk), pk);
    auto packed_values = pvac::dec_values(pk, sk, packed_round);
    for (size_t i = 0; i < 3; ++i) {
        uint64_t expected = i == 0 ? 1 : i == 1 ? 16 : 81;
        if (packed_values[i].lo != expected || packed_values[i].hi != 0)
            throw std::runtime_error("packed evolved roundtrip failed");
    }
    bool truncated = false, wrong_context = false, wrong_key = false;
    try { auto short_enc = enc; short_enc.pop_back(); (void)decode_ct(short_enc, pk); }
    catch (...) { truncated = true; }
    try { (void)decode_ct(enc, other); }
    catch (...) { wrong_context = true; }
    try {
        auto wrong = pvac::dec_value(other, osk, c);
        wrong_key = wrong.lo != 42 || wrong.hi != 0;
    } catch (...) { wrong_key = true; }
    if (!truncated || !wrong_context || !wrong_key) throw std::runtime_error("negative serialization control failed");
    out << "{\"selftest\":\"PASS\",\"ct_roundtrip\":true,\"pk_roundtrip\":true,"
        << "\"functional_pk_roundtrip\":true,\"full_field_roundtrip\":true,\"packed_evolved_roundtrip\":true,"
        << "\"truncated_rejected\":true,\"wrong_context_rejected\":true,\"wrong_key_rejected\":true,"
        << "\"runtime_toeplitz_id\":" << runtime.id << ",\"kernel\":\"" << runtime.name << "\""
        << ",\"kernel_selection_ms\":" << runtime.selection_ms
        << ",\"ct_bytes\":" << enc.size() << ",\"pk_bytes\":" << pkenc.size() << "}\n";
    if (!out) throw std::runtime_error("output write failed");
    out.close();
    write_rusage(output);
    return 0;
}

int main(int argc, char** argv) {
    try {
        std::string name = "S-add", output, key_output;
        int repetitions = 1, warmups = 1, batch = 1, fixture_count = 1, threads = 1;
        for (int i = 1; i < argc; ++i) {
            std::string a = argv[i];
            auto next = [&]() -> std::string { if (++i == argc) throw std::runtime_error("missing argument"); return argv[i]; };
            if (a == "--case") name = next();
            else if (a == "--output") output = next();
            else if (a == "--key-output") key_output = next();
            else if (a == "--repetitions") repetitions = std::stoi(next());
            else if (a == "--warmups") warmups = std::stoi(next());
            else if (a == "--batch") batch = std::stoi(next());
            else if (a == "--threads") threads = std::stoi(next());
            else if (a == "--fixture-count") fixture_count = std::stoi(next());
            else if (a == "--selftest") name = "selftest";
            else throw std::runtime_error("unknown argument: " + a);
        }
        if (output.empty() || repetitions < 1 || warmups < 0 || batch < 1 || fixture_count < 1 ||
            (batch != 1 && name != "S-add") || (threads != 1 && threads != 4))
            throw std::runtime_error("invalid arguments");
        if (name == "selftest") return selftest(output);
        std::ofstream out(output);
        if (!out) throw std::runtime_error("cannot open output file");
        size_t n = (name == "V64" || name == "D64") ? 64 : 1;
        pvac::Params p;
        PubKey pk;
        SecKey sk;
        auto runtime = checked_pvac_kernel();
        auto k0 = Clock::now();
        pvac::keygen(p, pk, sk);
        double keygen_ms = ms(k0, Clock::now());
        auto pk_bytes = encode_pk(pk);
        if (!key_output.empty()) {
            std::ofstream k(key_output, std::ios::binary);
            if (!k) throw std::runtime_error("cannot open key output");
            k.write(reinterpret_cast<const char*>(pk_bytes.data()), pk_bytes.size());
            if (!k) throw std::runtime_error("key output write failed");
        }
        for (int fixture_index = 0; fixture_index < fixture_count; ++fixture_index) {
        auto x = read_vec(), y = read_vec();
        if (x.size() != n) throw std::runtime_error("wrong x shape");
        if ((name == "S-add" || name == "S-mul" || name == "V64" || name == "D64" ||
             name.rfind("CH", 0) == 0) && y.size() != n) throw std::runtime_error("wrong y shape");
        auto encrypted = encrypt(pk, sk, name, x, y);
        auto base = std::move(encrypted.first);
        std::vector<double> eval_ms, dec_ms, copy_ms, warmup_eval_ms, warmup_dec_ms;
        std::vector<double> decrypt_batch_ms, output_bytes;
        std::vector<uint64_t> lo, hi, wlo, whi, elo, ehi;
        std::vector<uint64_t> output_ciphertext_bytes, batch_output_bytes;
        for (int w = 0; w < warmups; ++w) {
            auto input = base;
            auto t0 = Clock::now();
            auto c = evaluate(pk, name, input);
            warmup_eval_ms.push_back(ms(t0, Clock::now()));
            auto d0 = Clock::now();
            values(pk, sk, c, wlo, whi);
            warmup_dec_ms.push_back(ms(d0, Clock::now()));
        }
        for (int r = 0; r < repetitions; ++r) {
            auto c0 = Clock::now();
            auto input = base;
            copy_ms.push_back(ms(c0, Clock::now()));
            std::vector<Cipher> results;
            auto t0 = Clock::now();
            for (int j = 0; j < batch; ++j) results.push_back(evaluate(pk, name, input));
            eval_ms.push_back(ms(t0, Clock::now()) / batch);
            double batch_dec_ms = 0;
            uint64_t batch_bytes = 0;
            for (const auto& c : results) {
                auto d0 = Clock::now();
                values(pk, sk, c, lo, hi);
                batch_dec_ms += ms(d0, Clock::now());
                size_t encoded_size = encode_ct(c, pk).size();
                batch_bytes += encoded_size;
                output_ciphertext_bytes.push_back(encoded_size);
            }
            dec_ms.push_back(batch_dec_ms / batch);
            decrypt_batch_ms.push_back(batch_dec_ms);
            output_bytes.push_back(static_cast<double>(batch_bytes) / batch);
            batch_output_bytes.push_back(batch_bytes);
        }
        auto e0 = Clock::now();
        auto fresh = encrypt(pk, sk, name, x, y).first;
        auto final = evaluate(pk, name, fresh);
        values(pk, sk, final, elo, ehi);
        double e2e_ms = ms(e0, Clock::now());
        size_t input_bytes = 0;
        for (const auto& c : base) input_bytes += encode_ct(c, pk).size();
        size_t logical = name == "V64" ? 64 : 1;
        size_t count = repetitions * batch * logical;
        out << std::setprecision(17)
            << "{\"backend\":\"pvac\",\"case\":\"" << name << "\","
            << "\"fixture_index\":" << fixture_index << ",\"fixture_count\":" << fixture_count << ","
            << "\"source\":\"071b0e909c119de815e284b347c4bd979cb59ef3\","
            << "\"encryption_key_model\":\"secret_key\",\"depth_hint\":0,\"ct_mul_width\":8,"
            << "\"requested_threads\":" << threads << ",\"observed_threads\":1,"
            << "\"parallelism\":\"single-threaded implementation, a four-worker budget does not create parallel PVAC workers\","
            << "\"fresh_key_per_session\":true,"
            << "\"kernel\":\"" << runtime.name << "\",\"runtime_toeplitz_id\":" << runtime.id
            << ",\"runtime_toeplitz_id_at_completion\":" << pvac::g_toep_id
            << ",\"kernel_selection_ms\":" << runtime.selection_ms
            << ",\"compiled_kernel\":\"" <<
#if defined(__PCLMUL__)
            "gf2_conv_clmul"
#elif defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
            "gf2_conv_pmull"
#else
            "gf2_conv_scalar"
#endif
            << "\",\"compiler_flags\":\"" << PVAC_COMPILER_FLAGS << "\","
            << "\"security_status\":\"concrete whole-construction security unestablished\","
            << "\"serialization\":\"experimental PVCB0001, all dynamic payloads, little-endian, not production wire\","
            << "\"layout\":\"" << (name == "V64" ? "64-slot ciphertext" : "scalar ciphertexts") << "\","
            << "\"timing_units\":\"eval_ms=mean per logical evaluation per timed batch, decrypt_ms=mean whole-request decryption per evaluation, output_bytes=mean serialized bytes per evaluation\","
            << "\"logical_outputs\":" << logical
            << ",\"physical_input_ciphertexts\":" << base.size()
            << ",\"input_bytes\":" << input_bytes << ",\"public_key_bytes\":" << pk_bytes.size()
            << ",\"keygen_ms\":";
        if (fixture_index == 0) out << keygen_ms; else out << "null";
        out << ",\"encryption_ms\":" << encrypted.second
            << ",\"e2e_ms\":" << e2e_ms << ",\"batch_size\":" << batch
            << ",\"copy_reset_ms\":" << nums(copy_ms) << ",\"eval_ms\":" << nums(eval_ms)
            << ",\"decrypt_ms\":" << nums(dec_ms) << ",\"decrypt_batch_ms\":" << nums(decrypt_batch_ms)
            << ",\"output_bytes\":" << nums(output_bytes) << ",\"batch_output_bytes\":" << nums(batch_output_bytes)
            << ",\"output_ciphertext_bytes\":" << nums(output_ciphertext_bytes)
            << ",\"warmup_eval_ms\":" << nums(warmup_eval_ms) << ",\"warmup_decrypt_ms\":" << nums(warmup_dec_ms)
            << ",\"warmup_values_lo\":" << nums(wlo) << ",\"warmup_values_hi\":" << nums(whi)
            << ",\"values_lo\":" << nums(lo) << ",\"values_hi\":" << nums(hi)
            << ",\"e2e_values_lo\":" << nums(elo) << ",\"e2e_values_hi\":" << nums(ehi)
            << ",\"expected_value_count\":" << count << "}\n";
        }
        if (!out) throw std::runtime_error("output write failed");
        out.close();
        write_rusage(output);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "pvac_bench: " << e.what() << '\n';
        return 2;
    }
}
