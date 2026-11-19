#define main openfhe_small_harness_main
#include "openfhe_bench.cpp"
#undef main

#include "wide_integer.hpp"

static const std::vector<uint64_t> CRT_PRIMES{1073741827, 1073741831, 1073741833, 1073741839, 1073741843,
                                              1073741857, 1073741891, 1073741909, 1073741939};

static bool wide_case(const std::string& name) {
    return name == "I63-add" || name == "I63-mul" || name == "F127-add" || name == "F127-mul" ||
           name == "D25-d1" || name == "D25-d2" || name == "D25-d4";
}

static size_t wide_depth(const std::string& name) {
    return name.rfind("D25-d", 0) == 0 ? std::stoull(name.substr(5)) : 0;
}

static size_t wide_input_count(const std::string& name) {
    return name.rfind("D25-d", 0) == 0 ? wide_depth(name) + 1 : 2;
}

static BigUInt wide_lift_bound(const std::string& name, bool context = false) {
    if (name == "I63-add") return BigUInt(uint64_t{1} << 63).mul_small(2) - BigUInt(2);
    if (name == "I63-mul") {
        BigUInt value = BigUInt(uint64_t{1} << 63) - BigUInt(1);
        return value * value;
    }
    if (name == "F127-add") return (mersenne127_prime() - BigUInt(1)).mul_small(2);
    if (name == "F127-mul") {
        BigUInt value = mersenne127_prime() - BigUInt(1);
        return value * value;
    }
    size_t count = context ? 5 : wide_input_count(name);
    BigUInt value(1), factor = BigUInt(uint64_t{1} << 25) - BigUInt(1);
    for (size_t i = 0; i < count; ++i) value = value * factor;
    return value;
}

static void check_wide_domain(const BigUInt& value, const std::string& name) {
    BigUInt limit = name.rfind("I63", 0) == 0 ? BigUInt(uint64_t{1} << 63) :
                    name.rfind("D25", 0) == 0 ? BigUInt(uint64_t{1} << 25) : mersenne127_prime();
    if (value.compare(limit) >= 0) throw std::runtime_error("wide input outside declared domain");
}

struct WideSpec {
    std::string representation;
    std::string key_switch = "AUTO";
    uint32_t radix = 2;
    uint64_t plaintext_modulus = 65537;
    size_t coefficients = 1;
    size_t context_depth = 1;
    std::vector<uint64_t> moduli;
    BigUInt crt_capacity;
};

static WideSpec wide_spec(const std::string& name, const std::string& representation) {
    WideSpec spec;
    spec.representation = representation;
    const bool depth = name.rfind("D25", 0) == 0;
    const bool addition = name.size() > 3 && name.compare(name.size() - 3, 3, "add") == 0;
    spec.context_depth = depth ? 4 : addition ? 0 : 1;
    const size_t bits = depth ? 25 : name.rfind("I63", 0) == 0 ? 63 : 127;
    if (representation == "coef-binary" || representation == "coef-radix") {
        spec.radix = representation == "coef-binary" ? 2 : depth ? 4 : 32;
        spec.plaintext_modulus = representation == "coef-binary" && depth ? 786433 :
                                 representation == "coef-radix" && depth ? 16777213 : 65537;
        spec.coefficients = (bits + (spec.radix == 2 ? 1 : spec.radix == 4 ? 2 : 5) - 1) /
                            (spec.radix == 2 ? 1 : spec.radix == 4 ? 2 : 5);
        return spec;
    }
    if (representation != "crt30") throw std::runtime_error("unknown wide representation");
    spec.radix = 0;
    BigUInt capacity(1), bound = wide_lift_bound(name, true);
    for (uint64_t prime : CRT_PRIMES) {
        spec.moduli.push_back(prime);
        capacity = capacity.mul_small(static_cast<uint32_t>(prime));
        if (capacity.compare(bound) > 0) break;
    }
    if (capacity.compare(bound) <= 0) throw std::runtime_error("insufficient CRT capacity");
    spec.crt_capacity = capacity;
    return spec;
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

static std::vector<int64_t> wide_digits(BigUInt value, const WideSpec& spec) {
    std::vector<int64_t> digits;
    for (size_t i = 0; i < spec.coefficients; ++i) digits.push_back(value.divmod_small(spec.radix));
    if (!value.zero()) throw std::runtime_error("wide digit decomposition dropped high digits");
    return digits;
}

static std::vector<int64_t> add_coefficients(const std::vector<int64_t>& a, const std::vector<int64_t>& b) {
    if (a.size() != b.size()) throw std::runtime_error("coefficient shape mismatch");
    std::vector<int64_t> out(a.size());
    for (size_t i = 0; i < a.size(); ++i) out[i] = a[i] + b[i];
    return out;
}

static std::vector<int64_t> convolve(const std::vector<int64_t>& a, const std::vector<int64_t>& b) {
    std::vector<int64_t> out(a.size() + b.size() - 1, 0);
    for (size_t i = 0; i < a.size(); ++i) {
        for (size_t j = 0; j < b.size(); ++j) {
            int64_t next = out[i + j] + a[i] * b[j];
            if (next < 0) throw std::runtime_error("coefficient oracle overflow");
            out[i + j] = next;
        }
    }
    return out;
}

static std::vector<int64_t> coefficient_oracle(const std::string& name, const WideSpec& spec,
        const std::vector<std::string>& x, const std::vector<std::string>& y) {
    std::vector<std::vector<int64_t>> inputs;
    for (size_t i = 0; i < x.size(); ++i) {
        BigUInt value = BigUInt::decimal(x[i]);
        check_wide_domain(value, name);
        if (i < wide_input_count(name)) inputs.push_back(wide_digits(value, spec));
    }
    for (const auto& text : y) {
        BigUInt value = BigUInt::decimal(text);
        check_wide_domain(value, name);
        inputs.push_back(wide_digits(value, spec));
    }
    if (name.size() > 3 && name.compare(name.size() - 3, 3, "add") == 0)
        return add_coefficients(inputs[0], inputs[1]);
    auto result = inputs[0];
    for (size_t i = 1; i < inputs.size(); ++i) result = convolve(result, inputs[i]);
    return result;
}

struct WideContext {
    WideSpec spec;
    std::vector<Context> channels;
    double keygen_ms = 0;
};

static std::string selected_key_switch(const std::string& backend, size_t depth, const std::string& requested) {
    if (requested == "AUTO") return backend == "bfv" && depth >= 4 ? "BV" : "HYBRID";
    return requested;
}

static Context make_wide_channel(const std::string& backend, uint64_t plaintext_modulus, size_t depth, const std::string& key_switch) {
    auto start = Clock::now();
    Context c;
    CCParams<CryptoContextBFVRNS> bfv;
    CCParams<CryptoContextBGVRNS> bgv;
    auto selected = selected_key_switch(backend, depth, key_switch);
    if (backend == "bfv") {
        bfv.SetPlaintextModulus(plaintext_modulus);
        bfv.SetMultiplicativeDepth(depth);
        bfv.SetSecurityLevel(HEStd_128_classic);
        bfv.SetKeySwitchTechnique(selected == "BV" ? BV : HYBRID);
        bfv.SetMultiplicationTechnique(HPS);
        c.cc = GenCryptoContext(bfv);
    } else if (backend == "bgv") {
        bgv.SetPlaintextModulus(plaintext_modulus);
        bgv.SetMultiplicativeDepth(depth);
        bgv.SetSecurityLevel(HEStd_128_classic);
        bgv.SetScalingTechnique(FIXEDAUTO);
        bgv.SetKeySwitchTechnique(selected == "BV" ? BV : HYBRID);
        c.cc = GenCryptoContext(bgv);
    } else {
        throw std::runtime_error("wide OpenFHE backend must be BFV or BGV");
    }
    c.cc->Enable(PKE);
    c.cc->Enable(KEYSWITCH);
    c.cc->Enable(LEVELEDSHE);
    c.cc->Enable(ADVANCEDSHE);
    c.slots = c.cc->GetRingDimension();
    c.keys = c.cc->KeyGen();
    if (depth) c.cc->EvalMultKeyGen(c.keys.secretKey);
    c.keygen_ms = ms(start, Clock::now());
    return c;
}

static WideContext make_wide_context(const std::string& backend, const std::string& name, const std::string& representation,
                                     const std::string& key_switch) {
    WideContext result;
    result.spec = wide_spec(name, representation);
    result.spec.key_switch = key_switch;
    auto start = Clock::now();
    if (result.spec.moduli.empty()) {
        result.channels.push_back(make_wide_channel(backend, result.spec.plaintext_modulus, result.spec.context_depth, key_switch));
    } else {
        for (uint64_t modulus : result.spec.moduli)
            result.channels.push_back(make_wide_channel(backend, modulus, result.spec.context_depth, key_switch));
    }
    result.keygen_ms = ms(start, Clock::now());
    return result;
}

static void check_coefficient_bounds(const WideContext& context, const std::string& name) {
    if (context.spec.radix == 0) return;
    const size_t length = context.spec.coefficients;
    const size_t count = name.rfind("D25", 0) == 0 ? 5 : wide_input_count(name);
    const size_t degree = (name.size() > 3 && name.compare(name.size() - 3, 3, "add") == 0) ? length - 1 : count * (length - 1);
    for (const auto& channel : context.channels) {
        if (channel.cc->GetRingDimension() <= degree) throw std::runtime_error("degree wrap prevented by ring bound");
    }
    if (name.size() > 3 && name.compare(name.size() - 3, 3, "add") == 0) return;
    for (size_t factors = 2; factors <= count; ++factors) {
        unsigned __int128 bound = 1;
        for (size_t i = 1; i < factors; ++i) bound *= length;
        for (size_t i = 0; i < factors; ++i) bound *= context.spec.radix - 1;
        if (bound >= context.spec.plaintext_modulus / 2) throw std::runtime_error("coefficient wrap prevented by plaintext bound");
    }
}

static std::pair<std::vector<CT>, double> encrypt_wide(const WideContext& context, const std::string& name,
        const std::vector<std::string>& x, const std::vector<std::string>& y) {
    auto start = Clock::now();
    std::vector<BigUInt> clear;
    for (size_t i = 0; i < x.size(); ++i) {
        BigUInt value = BigUInt::decimal(x[i]);
        check_wide_domain(value, name);
        if (i < wide_input_count(name)) clear.push_back(value);
    }
    for (const auto& text : y) {
        BigUInt value = BigUInt::decimal(text);
        check_wide_domain(value, name);
        clear.push_back(value);
    }
    std::vector<CT> inputs;
    if (context.spec.radix) {
        for (const auto& value : clear) {
            auto digits = wide_digits(value, context.spec);
            auto plaintext = context.channels[0].cc->MakeCoefPackedPlaintext(digits);
            inputs.push_back(context.channels[0].cc->Encrypt(context.channels[0].keys.publicKey, plaintext));
        }
    } else {
        for (size_t channel = 0; channel < context.channels.size(); ++channel) {
            for (auto value : clear) {
                int64_t modulus = static_cast<int64_t>(context.spec.moduli[channel]);
                int64_t residue = static_cast<int64_t>(value.divmod_small(static_cast<uint32_t>(modulus)));
                if (residue > modulus / 2) residue -= modulus;
                auto plaintext = context.channels[channel].cc->MakeCoefPackedPlaintext({residue});
                inputs.push_back(context.channels[channel].cc->Encrypt(context.channels[channel].keys.publicKey, plaintext));
            }
        }
    }
    return {std::move(inputs), ms(start, Clock::now())};
}

static CT evaluate_channel(const Context& context, const std::string& name, const std::vector<CT>& inputs) {
    if (name.size() > 3 && name.compare(name.size() - 3, 3, "add") == 0)
        return context.cc->EvalAdd(inputs[0], inputs[1]);
    CT result = inputs[0];
    for (size_t i = 1; i < inputs.size(); ++i) result = context.cc->EvalMult(result, inputs[i]);
    return result;
}

static std::vector<CT> evaluate_wide(const WideContext& context, const std::string& name, const std::vector<CT>& base) {
    const size_t inputs = wide_input_count(name);
    std::vector<CT> results;
    if (context.spec.radix) return {evaluate_channel(context.channels[0], name, base)};
    for (size_t channel = 0; channel < context.channels.size(); ++channel) {
        std::vector<CT> slice(base.begin() + channel * inputs, base.begin() + (channel + 1) * inputs);
        results.push_back(evaluate_channel(context.channels[channel], name, slice));
    }
    return results;
}

struct WideDecoded {
    BigUInt lifted;
    BigUInt answer;
    std::vector<int64_t> coefficients;
};

static WideDecoded decode_wide(const WideContext& context, const std::string& name, const std::vector<CT>& results) {
    WideDecoded decoded;
    if (context.spec.radix) {
        Plaintext plaintext;
        context.channels[0].cc->Decrypt(context.channels[0].keys.secretKey, results[0], &plaintext);
        size_t ring = context.channels[0].cc->GetRingDimension();
        plaintext->SetLength(ring);
        decoded.coefficients = plaintext->GetCoefPackedValue();
        if (decoded.coefficients.size() != ring) throw std::runtime_error("short full-ring coefficient decode");
        BigUInt lifted;
        size_t shift = context.spec.radix == 2 ? 1 : context.spec.radix == 4 ? 2 : 5;
        for (size_t i = 0; i < decoded.coefficients.size(); ++i) {
            int64_t coefficient = decoded.coefficients[i];
            if (coefficient < 0 || static_cast<uint64_t>(coefficient) >= context.spec.plaintext_modulus / 2)
                throw std::runtime_error("coefficient left the proved signed decode interval");
            if (coefficient) lifted = lifted + BigUInt(static_cast<uint64_t>(coefficient)).shl(i * shift);
        }
        decoded.lifted = lifted;
    } else {
        std::vector<uint64_t> residues;
        for (size_t channel = 0; channel < context.channels.size(); ++channel) {
            Plaintext plaintext;
            context.channels[channel].cc->Decrypt(context.channels[channel].keys.secretKey, results[channel], &plaintext);
            plaintext->SetLength(1);
            auto values = plaintext->GetCoefPackedValue();
            if (values.size() != 1) throw std::runtime_error("invalid CRT scalar decode");
            int64_t value = values[0];
            int64_t modulus = static_cast<int64_t>(context.spec.moduli[channel]);
            if (value < 0) value += modulus;
            if (value < 0 || value >= modulus) throw std::runtime_error("invalid CRT signed residue");
            residues.push_back(static_cast<uint64_t>(value));
        }
        decoded.lifted = crt_reconstruct(residues, context.spec.moduli);
    }
    decoded.answer = name.rfind("F127", 0) == 0 ? mersenne127_mod(decoded.lifted) : decoded.lifted;
    return decoded;
}

static void check_coefficient_oracle(const WideDecoded& decoded, const std::vector<int64_t>& expected) {
    if (expected.empty()) return;
    if (decoded.coefficients.size() < expected.size()) throw std::runtime_error("dropped high coefficient");
    for (size_t i = 0; i < decoded.coefficients.size(); ++i) {
        int64_t reference = i < expected.size() ? expected[i] : 0;
        if (decoded.coefficients[i] != reference) throw std::runtime_error("independent coefficient oracle mismatch");
    }
}

int main(int argc, char** argv) {
    try {
        std::string backend = "bfv", name = "F127-mul", representation = "coef-binary", key_switch = "AUTO", output;
        int repetitions = 1, warmups = 1, batch = 1, threads = 1, fixture_count = 1;
        for (int i = 1; i < argc; ++i) {
            std::string a = argv[i];
            auto next = [&]() -> std::string { if (++i == argc) throw std::runtime_error("missing argument"); return argv[i]; };
            if (a == "--backend") backend = next();
            else if (a == "--case") name = next();
            else if (a == "--representation") representation = next();
            else if (a == "--key-switch") key_switch = next();
            else if (a == "--output") output = next();
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
        if ((key_switch != "AUTO" && key_switch != "HYBRID" && key_switch != "BV") ||
            (backend == "bgv" && key_switch == "BV")) throw std::runtime_error("invalid key-switch candidate");
        if (name == "selftest") {
            wide_integer_selftest();
            return selftest(backend, output);
        }
        if (!wide_case(name) || (backend != "bfv" && backend != "bgv")) throw std::runtime_error("unknown wide case or backend");
        std::ofstream out(output);
        if (!out) throw std::runtime_error("cannot open output file");
#ifdef _OPENMP
        omp_set_dynamic(0);
        OpenFHEParallelControls.SetNumThreads(threads);
        int observed_threads = 0;
#pragma omp parallel num_threads(threads)
        {
#pragma omp single
            observed_threads = omp_get_num_threads();
        }
        if (observed_threads != threads) throw std::runtime_error("OpenMP worker profile mismatch");
        int controller_threads = OpenFHEParallelControls.GetNumThreads();
        int machine_threads = OpenFHEParallelControls.GetMachineThreads();
#else
        if (threads != 1) throw std::runtime_error("OpenMP required for multicore profile");
        int observed_threads = 1, controller_threads = 1, machine_threads = 1;
#endif
        auto context = make_wide_context(backend, name, representation, key_switch);
        check_coefficient_bounds(context, name);
        const size_t nx = name.rfind("D25", 0) == 0 ? 5 : 1;
        const size_t ny = name.rfind("D25", 0) == 0 ? 0 : 1;
        for (int fixture_index = 0; fixture_index < fixture_count; ++fixture_index) {
            auto x = read_wide_vec(), y = read_wide_vec();
            if (x.size() != nx || y.size() != ny) throw std::runtime_error("wide input shape mismatch");
            std::vector<int64_t> expected;
            if (context.spec.radix) expected = coefficient_oracle(name, context.spec, x, y);
            auto encrypted = encrypt_wide(context, name, x, y);
            auto base = std::move(encrypted.first);
            std::vector<double> eval_ms, dec_ms, copy_ms, warmup_eval_ms, warmup_dec_ms;
            std::vector<double> decrypt_batch_ms, output_bytes, output_scales;
            std::vector<uint64_t> output_ciphertext_bytes, batch_output_bytes, output_levels;
            std::vector<std::string> values, warm_values, e2e_values, lift_values, warm_lift, e2e_lift;
            for (int w = 0; w < warmups; ++w) {
                std::vector<CT> input;
                for (const auto& ct : base) input.push_back(ct->Clone());
                auto t0 = Clock::now();
                auto results = evaluate_wide(context, name, input);
                warmup_eval_ms.push_back(ms(t0, Clock::now()));
                auto d0 = Clock::now();
                auto decoded = decode_wide(context, name, results);
                warmup_dec_ms.push_back(ms(d0, Clock::now()));
                check_coefficient_oracle(decoded, expected);
                warm_values.push_back(decoded.answer.str());
                warm_lift.push_back(decoded.lifted.str());
            }
            for (int r = 0; r < repetitions; ++r) {
                auto copy_start = Clock::now();
                std::vector<CT> input;
                for (const auto& ct : base) input.push_back(ct->Clone());
                copy_ms.push_back(ms(copy_start, Clock::now()));
                std::vector<std::vector<CT>> evaluations;
                auto t0 = Clock::now();
                for (int j = 0; j < batch; ++j) evaluations.push_back(evaluate_wide(context, name, input));
                eval_ms.push_back(ms(t0, Clock::now()) / batch);
                double batch_dec_ms = 0;
                uint64_t batch_bytes = 0;
                for (const auto& results : evaluations) {
                    std::vector<CT> restored;
                    for (const auto& result : results) {
                        auto encoded = serialize(result);
                        batch_bytes += encoded.size();
                        output_ciphertext_bytes.push_back(encoded.size());
                        restored.push_back(roundtrip(encoded));
                        output_levels.push_back(result->GetLevel());
                        output_scales.push_back(result->GetScalingFactor());
                    }
                    auto d0 = Clock::now();
                    auto decoded = decode_wide(context, name, restored);
                    batch_dec_ms += ms(d0, Clock::now());
                    check_coefficient_oracle(decoded, expected);
                    values.push_back(decoded.answer.str());
                    lift_values.push_back(decoded.lifted.str());
                }
                dec_ms.push_back(batch_dec_ms / batch);
                decrypt_batch_ms.push_back(batch_dec_ms);
                output_bytes.push_back(static_cast<double>(batch_bytes) / batch);
                batch_output_bytes.push_back(batch_bytes);
            }
            auto e0 = Clock::now();
            auto fresh = encrypt_wide(context, name, x, y).first;
            auto final = evaluate_wide(context, name, fresh);
            auto decoded = decode_wide(context, name, final);
            double e2e_ms = ms(e0, Clock::now());
            check_coefficient_oracle(decoded, expected);
            e2e_values.push_back(decoded.answer.str());
            e2e_lift.push_back(decoded.lifted.str());
            uint64_t input_bytes = 0, public_bytes = 0, mult_bytes = 0;
            for (const auto& ct : base) input_bytes += serialize(ct).size();
            std::vector<std::string> parameter_parts;
            std::vector<uint64_t> ring_dimensions;
            for (const auto& channel : context.channels) {
                public_bytes += serialize_any(channel.keys.publicKey).size();
                if (context.spec.context_depth) {
                    for (const auto& key : channel.cc->GetEvalMultKeyVector(channel.keys.secretKey->GetKeyTag()))
                        mult_bytes += serialize_any(key).size();
                }
                parameter_parts.push_back(Serial::SerializeToString(channel.cc));
                ring_dimensions.push_back(channel.cc->GetRingDimension());
            }
            std::string parameters = context.channels.size() == 1 ? parameter_parts[0] : "[" + [&] {
                std::string joined;
                for (size_t i = 0; i < parameter_parts.size(); ++i) {
                    if (i) joined += ",";
                    joined += quote(parameter_parts[i]);
                }
                return joined;
            }() + "]";
            out << std::setprecision(17)
                << "{\"backend\":" << quote(backend) << ",\"case\":" << quote(name)
                << ",\"fixture_index\":" << fixture_index << ",\"fixture_count\":" << fixture_count << ","
                << "\"source\":\"b59e1f291965f14fbee5172cd83a20f5b856204f\","
                << "\"representation\":" << quote(representation)
                << ",\"key_switch_requested\":" << quote(context.spec.key_switch)
                << ",\"key_switch_technique\":" << quote(selected_key_switch(backend, context.spec.context_depth, context.spec.key_switch))
                << ",\"radix\":" << context.spec.radix << ",\"plaintext_modulus\":" << context.spec.plaintext_modulus
                << ",\"coefficients_per_input\":" << context.spec.coefficients
                << ",\"crt_channels\":" << context.channels.size()
                << ",\"crt_capacity\":\"" << context.spec.crt_capacity.str() << "\""
                << ",\"lifted_bound\":\"" << wide_lift_bound(name, true).str() << "\""
                << ",\"context_multiplicative_depth\":" << context.spec.context_depth
                << ",\"encryption_key_model\":\"public_key\",\"fresh_context_per_session\":true,"
                << "\"security_parameter\":\"HEStd_128_classic, library-selected parameters, no independent estimator validation\","
                << "\"serialization\":\"OpenFHE cereal portable binary, uncompressed\","
                << "\"wide_terminal_contract\":\"coefficient or CRT lift with client carry reconstruction and final Mersenne reduction\","
                << "\"requested_threads\":" << threads << ",\"observed_threads\":" << observed_threads
                << ",\"parallel_controls_limit\":" << controller_threads
                << ",\"parallel_controls_machine_threads\":" << machine_threads
                << ",\"parameters_json\":";
            if (fixture_index == 0) out << quote(parameters); else out << "null";
            out << ",\"keygen_ms\":";
            if (fixture_index == 0) out << context.keygen_ms; else out << "null";
            out << ",\"encryption_ms\":" << encrypted.second << ",\"e2e_ms\":" << e2e_ms
                << ",\"batch_size\":" << batch << ",\"copy_reset_ms\":" << nums(copy_ms)
                << ",\"eval_ms\":" << nums(eval_ms) << ",\"decrypt_ms\":" << nums(dec_ms)
                << ",\"decrypt_batch_ms\":" << nums(decrypt_batch_ms)
                << ",\"input_bytes\":" << input_bytes << ",\"public_key_bytes\":" << public_bytes
                << ",\"relinearization_key_bytes\":" << mult_bytes << ",\"rotation_key_bytes\":0"
                << ",\"logical_outputs\":1,\"physical_input_ciphertexts\":" << base.size()
                << ",\"physical_output_ciphertexts\":" << context.channels.size()
                << ",\"output_bytes\":" << nums(output_bytes) << ",\"batch_output_bytes\":" << nums(batch_output_bytes)
                << ",\"output_ciphertext_bytes\":" << nums(output_ciphertext_bytes)
                << ",\"output_levels\":" << nums(output_levels) << ",\"output_scales\":" << nums(output_scales)
                << ",\"warmup_eval_ms\":" << nums(warmup_eval_ms) << ",\"warmup_decrypt_ms\":" << nums(warmup_dec_ms)
                << ",\"warmup_values_decimal\":" << string_array(warm_values)
                << ",\"values_decimal\":" << string_array(values)
                << ",\"e2e_values_decimal\":" << string_array(e2e_values)
                << ",\"warmup_lift_decimal\":" << string_array(warm_lift)
                << ",\"lift_decimal\":" << string_array(lift_values)
                << ",\"e2e_lift_decimal\":" << string_array(e2e_lift)
                << ",\"expected_value_count\":" << (repetitions * batch);
            if (context.channels.size() == 1) out << ",\"ring_dimension\":" << ring_dimensions[0] << ",\"physical_slots\":" << ring_dimensions[0];
            out << ",\"ring_dimensions\":" << nums(ring_dimensions) << "}\n";
        }
        if (!out) throw std::runtime_error("output write failed");
        out.close();
        write_rusage(output);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "openfhe_wide_bench: " << e.what() << '\n';
        return 2;
    }
}
