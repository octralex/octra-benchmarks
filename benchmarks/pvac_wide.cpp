#define main pvac_small_harness_main
#include "pvac_bench.cpp"
#undef main

#include "wide_integer.hpp"

static bool wide_case(const std::string& name) {
    return name == "I63-add" || name == "I63-mul" || name == "F127-add" || name == "F127-mul" ||
           name == "D25-d1" || name == "D25-d2" || name == "D25-d4";
}

static size_t wide_depth(const std::string& name) {
    if (name.rfind("D25-d", 0) == 0) return std::stoull(name.substr(5));
    return 0;
}

static size_t wide_inputs(const std::string& name) {
    return name.rfind("D25-d", 0) == 0 ? wide_depth(name) + 1 : 2;
}

static pvac::Fp wide_fp(const BigUInt& value, const std::string& name) {
    const BigUInt limit = name.rfind("I63", 0) == 0 ? BigUInt(uint64_t{1} << 63) :
                          name.rfind("D25", 0) == 0 ? BigUInt(uint64_t{1} << 25) : mersenne127_prime();
    if (value.compare(limit) >= 0) throw std::runtime_error("wide input is outside its declared domain");
    if (value.w.size() > 4) throw std::runtime_error("field input overflow");
    uint64_t lo = value.w.empty() ? 0 : value.w[0];
    uint64_t hi = value.w.size() > 2 ? value.w[2] : 0;
    if (value.w.size() > 1) lo |= static_cast<uint64_t>(value.w[1]) << 32;
    if (value.w.size() > 3) hi |= static_cast<uint64_t>(value.w[3]) << 32;
    return pvac::Fp{lo, hi};
}

static BigUInt wide_big(uint64_t lo, uint64_t hi) {
    BigUInt value;
    if (hi > pvac::MASK63 || (hi == pvac::MASK63 && lo == UINT64_MAX)) throw std::runtime_error("noncanonical PVAC output");
    if (lo || hi) value.w = {static_cast<uint32_t>(lo), static_cast<uint32_t>(lo >> 32),
                            static_cast<uint32_t>(hi), static_cast<uint32_t>(hi >> 32)};
    value.normalize();
    return value;
}

static std::vector<std::string> read_wide_vec() {
    std::string line;
    if (!std::getline(std::cin, line)) throw std::runtime_error("missing wide input vector");
    std::stringstream ss(line);
    std::vector<std::string> values;
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (item.empty()) throw std::runtime_error("empty wide input");
        (void)BigUInt::decimal(item);
        values.push_back(item);
    }
    return values;
}

static std::string string_array(const std::vector<std::string>& values) {
    std::ostringstream out;
    out << '[';
    for (size_t i = 0; i < values.size(); ++i) {
        if (i) out << ',';
        out << '"' << values[i] << '"';
    }
    return out.str() + "]";
}

static std::pair<std::vector<Cipher>, double> encrypt_wide(const PubKey& pk, const SecKey& sk,
        const std::string& name, const std::vector<std::string>& x, const std::vector<std::string>& y) {
    auto start = Clock::now();
    std::vector<Cipher> inputs;
    for (size_t i = 0; i < x.size(); ++i) {
        auto value = wide_fp(BigUInt::decimal(x[i]), name);
        if (i < wide_inputs(name)) inputs.push_back(pvac::enc_fp_wrapped_depth(pk, sk, value, 0));
    }
    for (const auto& text : y) inputs.push_back(pvac::enc_fp_wrapped_depth(pk, sk, wide_fp(BigUInt::decimal(text), name), 0));
    return {std::move(inputs), ms(start, Clock::now())};
}

static Cipher evaluate_wide(const PubKey& pk, const std::string& name, const std::vector<Cipher>& in) {
    if (name == "I63-add" || name == "F127-add") return pvac::ct_add(pk, in[0], in[1]);
    if (name == "I63-mul" || name == "F127-mul") return pvac::ct_mul(pk, in[0], in[1]);
    if (name.rfind("D25-d", 0) == 0) {
        Cipher acc = in[0];
        for (size_t i = 1; i < in.size(); ++i) acc = pvac::ct_mul(pk, acc, in[i]);
        return acc;
    }
    throw std::runtime_error("unknown wide case");
}

int main(int argc, char** argv) {
    try {
        std::string name = "F127-mul", output, key_output;
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
            (batch != 1 && name != "I63-add" && name != "F127-add") || (threads != 1 && threads != 4))
            throw std::runtime_error("invalid wide arguments");
        if (name == "selftest") {
            wide_integer_selftest();
            return selftest(output);
        }
        if (!wide_case(name)) throw std::runtime_error("unknown wide case");
        std::ofstream out(output);
        if (!out) throw std::runtime_error("cannot open output file");
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
        const size_t nx = name.rfind("D25", 0) == 0 ? 5 : 1;
        const size_t ny = name.rfind("D25", 0) == 0 ? 0 : 1;
        for (int fixture_index = 0; fixture_index < fixture_count; ++fixture_index) {
            auto x = read_wide_vec(), y = read_wide_vec();
            if (x.size() != nx || y.size() != ny) throw std::runtime_error("wide input shape mismatch");
            auto encrypted = encrypt_wide(pk, sk, name, x, y);
            auto base = std::move(encrypted.first);
            std::vector<double> eval_ms, dec_ms, copy_ms, warmup_eval_ms, warmup_dec_ms;
            std::vector<double> decrypt_batch_ms, output_bytes;
            std::vector<uint64_t> lo, hi, wlo, whi, elo, ehi, output_ciphertext_bytes, batch_output_bytes;
            std::vector<std::string> values, warm_values, e2e_values, lift_values, warm_lift, e2e_lift;
            auto append = [&](const Cipher& c, std::vector<uint64_t>& lows, std::vector<uint64_t>& highs,
                              std::vector<std::string>& decimals, std::vector<std::string>& lifts) {
                auto decoded = pvac::dec_values(pk, sk, c);
                if (decoded.size() != 1) throw std::runtime_error("wide output shape mismatch");
                lows.push_back(decoded[0].lo);
                highs.push_back(decoded[0].hi);
                auto text = wide_big(decoded[0].lo, decoded[0].hi).str();
                decimals.push_back(text);
                lifts.push_back(text);
            };
            for (int w = 0; w < warmups; ++w) {
                auto input = base;
                auto t0 = Clock::now();
                auto result = evaluate_wide(pk, name, input);
                warmup_eval_ms.push_back(ms(t0, Clock::now()));
                auto d0 = Clock::now();
                append(result, wlo, whi, warm_values, warm_lift);
                warmup_dec_ms.push_back(ms(d0, Clock::now()));
            }
            for (int r = 0; r < repetitions; ++r) {
                auto c0 = Clock::now();
                auto input = base;
                copy_ms.push_back(ms(c0, Clock::now()));
                std::vector<Cipher> results;
                auto t0 = Clock::now();
                for (int j = 0; j < batch; ++j) results.push_back(evaluate_wide(pk, name, input));
                eval_ms.push_back(ms(t0, Clock::now()) / batch);
                double batch_dec_ms = 0;
                uint64_t batch_bytes = 0;
                for (const auto& result : results) {
                    auto encoded = encode_ct(result, pk);
                    auto restored = decode_ct(encoded, pk);
                    auto d0 = Clock::now();
                    append(restored, lo, hi, values, lift_values);
                    batch_dec_ms += ms(d0, Clock::now());
                    batch_bytes += encoded.size();
                    output_ciphertext_bytes.push_back(encoded.size());
                }
                dec_ms.push_back(batch_dec_ms / batch);
                decrypt_batch_ms.push_back(batch_dec_ms);
                output_bytes.push_back(static_cast<double>(batch_bytes) / batch);
                batch_output_bytes.push_back(batch_bytes);
            }
            auto e0 = Clock::now();
            auto fresh = encrypt_wide(pk, sk, name, x, y).first;
            auto final = evaluate_wide(pk, name, fresh);
            append(final, elo, ehi, e2e_values, e2e_lift);
            double e2e_ms = ms(e0, Clock::now());
            size_t input_bytes = 0;
            for (const auto& c : base) input_bytes += encode_ct(c, pk).size();
            out << std::setprecision(17)
                << "{\"backend\":\"pvac\",\"case\":\"" << name << "\","
                << "\"fixture_index\":" << fixture_index << ",\"fixture_count\":" << fixture_count << ","
                << "\"source\":\"071b0e909c119de815e284b347c4bd979cb59ef3\","
                << "\"encryption_key_model\":\"secret_key\",\"depth_hint\":0,\"ct_mul_width\":8,"
                << "\"requested_threads\":" << threads << ",\"observed_threads\":1,"
                << "\"parallelism\":\"single-threaded implementation, a four-worker budget does not create parallel PVAC workers\","
                << "\"fresh_key_per_session\":true,\"wide_terminal_contract\":true,"
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
                << "\"layout\":\"native full-field scalar, canonical residue at client\","
                << "\"timing_units\":\"eval_ms=mean per logical evaluation per timed batch, decrypt_ms=mean whole-request decryption per evaluation, output_bytes=mean serialized bytes per evaluation, batch_output_bytes=aggregate bytes per timed batch\","
                << "\"logical_outputs\":1,\"physical_input_ciphertexts\":" << base.size()
                << ",\"input_bytes\":" << input_bytes << ",\"public_key_bytes\":" << pk_bytes.size()
                << ",\"keygen_ms\":";
            if (fixture_index == 0) out << keygen_ms; else out << "null";
            out << ",\"encryption_ms\":" << encrypted.second << ",\"e2e_ms\":" << e2e_ms
                << ",\"batch_size\":" << batch << ",\"copy_reset_ms\":" << nums(copy_ms)
                << ",\"eval_ms\":" << nums(eval_ms) << ",\"decrypt_ms\":" << nums(dec_ms)
                << ",\"decrypt_batch_ms\":" << nums(decrypt_batch_ms)
                << ",\"output_bytes\":" << nums(output_bytes) << ",\"batch_output_bytes\":" << nums(batch_output_bytes)
                << ",\"output_ciphertext_bytes\":" << nums(output_ciphertext_bytes)
                << ",\"warmup_eval_ms\":" << nums(warmup_eval_ms) << ",\"warmup_decrypt_ms\":" << nums(warmup_dec_ms)
                << ",\"warmup_values_lo\":" << nums(wlo) << ",\"warmup_values_hi\":" << nums(whi)
                << ",\"values_lo\":" << nums(lo) << ",\"values_hi\":" << nums(hi)
                << ",\"e2e_values_lo\":" << nums(elo) << ",\"e2e_values_hi\":" << nums(ehi)
                << ",\"warmup_values_decimal\":" << string_array(warm_values)
                << ",\"values_decimal\":" << string_array(values)
                << ",\"e2e_values_decimal\":" << string_array(e2e_values)
                << ",\"warmup_lift_decimal\":" << string_array(warm_lift)
                << ",\"lift_decimal\":" << string_array(lift_values)
                << ",\"e2e_lift_decimal\":" << string_array(e2e_lift)
                << ",\"expected_value_count\":" << (repetitions * batch) << "}\n";
        }
        if (!out) throw std::runtime_error("output write failed");
        out.close();
        write_rusage(output);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "pvac_wide_bench: " << e.what() << '\n';
        return 2;
    }
}
