#include "openfhe.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "process_rusage.hpp"

#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <sys/resource.h>
#ifdef _OPENMP
#include <omp.h>
#endif

using Clock = std::chrono::steady_clock;
using namespace lbcrypto;
using CT = Ciphertext<DCRTPoly>;

struct Context {
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> keys;
    uint32_t slots = 0;
    double keygen_ms = 0;
};

static double ms(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

static int depth_of(const std::string& name) {
    if (name == "S-mul" || name == "V64" || name == "D64") return 1;
    if (name == "P3") return 2;
    if (name.rfind("CH", 0) == 0 || name.rfind("SQ", 0) == 0) return std::stoi(name.substr(2));
    if (name == "S-add") return 0;
    throw std::runtime_error("unknown case");
}

static Context make_context(const std::string& backend, const std::string& name) {
    auto start = Clock::now();
    Context c;
    int depth = depth_of(name);
    if (backend == "bfv") {
        CCParams<CryptoContextBFVRNS> p;
        p.SetPlaintextModulus(65537);
        p.SetMultiplicativeDepth(depth);
        p.SetSecurityLevel(HEStd_128_classic);
        p.SetKeySwitchTechnique(HYBRID);
        p.SetMultiplicationTechnique(HPS);
        c.cc = GenCryptoContext(p);
        c.slots = c.cc->GetRingDimension();
    } else if (backend == "bgv") {
        CCParams<CryptoContextBGVRNS> p;
        p.SetPlaintextModulus(65537);
        p.SetMultiplicativeDepth(depth);
        p.SetSecurityLevel(HEStd_128_classic);
        p.SetScalingTechnique(FIXEDAUTO);
        p.SetKeySwitchTechnique(HYBRID);
        c.cc = GenCryptoContext(p);
        c.slots = c.cc->GetRingDimension();
    } else if (backend == "ckks") {
        CCParams<CryptoContextCKKSRNS> p;
        p.SetMultiplicativeDepth(depth + (name == "S-add" ? 0 : 1));
        p.SetSecurityLevel(HEStd_128_classic);
        p.SetScalingModSize(50);
        p.SetFirstModSize(55);
        p.SetScalingTechnique(FIXEDMANUAL);
        p.SetKeySwitchTechnique(HYBRID);
        c.cc = GenCryptoContext(p);
        c.slots = c.cc->GetRingDimension() / 2;
    } else {
        throw std::runtime_error("unknown OpenFHE backend");
    }
    c.cc->Enable(PKE);
    c.cc->Enable(KEYSWITCH);
    c.cc->Enable(LEVELEDSHE);
    c.cc->Enable(ADVANCEDSHE);
    c.keys = c.cc->KeyGen();
    if (name != "S-add") c.cc->EvalMultKeyGen(c.keys.secretKey);
    if (name == "D64") c.cc->EvalRotateKeyGen(c.keys.secretKey, {1, 2, 4, 8, 16, 32});
    c.keygen_ms = ms(start, Clock::now());
    return c;
}

static Plaintext plain(const Context& c, const std::string& backend, const std::vector<int64_t>& v) {
    if (backend == "ckks") {
        std::vector<double> d(v.begin(), v.end());
        return c.cc->MakeCKKSPackedPlaintext(d);
    }
    return c.cc->MakePackedPlaintext(v);
}

static std::pair<std::vector<CT>, double> encrypt(const Context& c, const std::string& backend,
        const std::string& name, const std::vector<uint64_t>& x, const std::vector<uint64_t>& y) {
    auto start = Clock::now();
    std::vector<CT> in;
    auto pack = [&](const std::vector<uint64_t>& u) {
        std::vector<int64_t> v(u.begin(), u.end());
        return c.cc->Encrypt(c.keys.publicKey, plain(c, backend, v));
    };
    if (name == "V64" || name == "D64") {
        in.push_back(pack(x));
        in.push_back(pack(y));
    } else {
        in.push_back(pack(x));
        if (name == "S-add" || name == "S-mul" || name.rfind("CH", 0) == 0) in.push_back(pack(y));
    }
    return {std::move(in), ms(start, Clock::now())};
}

static CT pub_mul(const Context& c, const std::string& backend, const CT& a, int64_t k) {
    if (backend == "ckks") return c.cc->EvalMult(a, static_cast<double>(k));
    return c.cc->EvalMultNoCheck(a, lbcrypto::NativeInteger(k));
}

static CT pub_add(const Context& c, const std::string& backend, const CT& a, int64_t k) {
    if (backend == "ckks") return c.cc->EvalAdd(a, static_cast<double>(k));
    auto p = c.cc->MakePackedPlaintext({k}, 1, a->GetLevel());
    return c.cc->EvalAdd(a, p);
}

static CT ct_mul(const Context& c, const std::string& backend, const CT& a, const CT& b) {
    CT result = c.cc->EvalMult(a, b);
    if (backend == "ckks") c.cc->RescaleInPlace(result);
    return result;
}

static CT evaluate(const Context& c, const std::string& backend, const std::string& name,
                   const std::vector<CT>& in) {
    const auto& cc = c.cc;
    if (name == "S-add") return cc->EvalAdd(in[0], in[1]);
    if (name == "S-mul" || name == "V64") return ct_mul(c, backend, in[0], in[1]);
    if (name == "D64") {
        CT acc = ct_mul(c, backend, in[0], in[1]);
        for (uint32_t offset = 1; offset < 64; offset *= 2) {
            auto rotated = cc->EvalRotate(acc, offset);
            acc = cc->EvalAdd(acc, rotated);
        }
        return acc;
    }
    if (name == "P3") {
        CT t = pub_add(c, backend, pub_mul(c, backend, in[0], 3), 2);
        t = pub_add(c, backend, ct_mul(c, backend, t, in[0]), 5);
        return pub_add(c, backend, ct_mul(c, backend, t, in[0]), 7);
    }
    if (name.rfind("CH", 0) == 0) {
        CT t = in[0];
        for (int d = 0; d < depth_of(name); ++d) t = ct_mul(c, backend, t, in[1]);
        return t;
    }
    if (name.rfind("SQ", 0) == 0) {
        CT t = in[0];
        for (int d = 0; d < depth_of(name); ++d) t = ct_mul(c, backend, t, t);
        return t;
    }
    throw std::runtime_error("unknown case");
}

static std::vector<int64_t> decrypt_exact(const Context& c, const CT& ct, const std::string& name) {
    Plaintext p;
    c.cc->Decrypt(c.keys.secretKey, ct, &p);
    size_t n = name == "V64" ? 64 : 1;
    p->SetLength(n);
    auto v = p->GetPackedValue();
    if (v.size() < n) throw std::runtime_error("short decrypted plaintext");
    return std::vector<int64_t>(v.begin(), v.begin() + n);
}

static std::vector<double> decrypt_approx(const Context& c, const CT& ct, const std::string& name) {
    Plaintext p;
    c.cc->Decrypt(c.keys.secretKey, ct, &p);
    size_t n = name == "V64" ? 64 : 1;
    p->SetLength(n);
    auto v = p->GetCKKSPackedValue();
    if (v.size() < n) throw std::runtime_error("short decrypted plaintext");
    std::vector<double> out;
    for (size_t i = 0; i < n; ++i) {
        if (std::abs(v[i].imag()) > 1e-8) throw std::runtime_error("unexpected complex output");
        out.push_back(v[i].real());
    }
    return out;
}

static std::vector<uint64_t> read_vec() {
    std::string line;
    if (!std::getline(std::cin, line)) throw std::runtime_error("missing input vector");
    std::stringstream ss(line);
    std::vector<uint64_t> v;
    std::string item;
    while (std::getline(ss, item, ',')) if (!item.empty()) v.push_back(std::stoull(item));
    return v;
}

template <typename T> static std::string nums(const std::vector<T>& v) {
    std::ostringstream s;
    s << std::setprecision(17) << "[";
    for (size_t i = 0; i < v.size(); ++i) { if (i) s << ','; s << v[i]; }
    return s.str() + "]";
}

static std::string quote(const std::string& v) {
    std::ostringstream s;
    s << '"';
    for (unsigned char c : v) {
        if (c == '"' || c == '\\') s << '\\' << c;
        else if (c == '\n') s << "\\n";
        else if (c == '\r') s << "\\r";
        else if (c == '\t') s << "\\t";
        else if (c < 32) { s << "\\u00" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c); }
        else s << c;
    }
    return s.str() + '"';
}

template <typename T> static std::string serialize_any(const T& value) {
    std::ostringstream stream(std::ios::out | std::ios::binary);
    Serial::Serialize(value, stream, SerType::BINARY);
    if (!stream) throw std::runtime_error("binary serialization failed");
    return stream.str();
}

static std::string serialize(const CT& ct) { return serialize_any(ct); }

static CT roundtrip(const std::string& bytes) {
    CT result;
    std::istringstream stream(bytes, std::ios::in | std::ios::binary);
    Serial::Deserialize(result, stream, SerType::BINARY);
    if (!result) throw std::runtime_error("null deserialized ciphertext");
    if (stream.peek() != std::char_traits<char>::eof()) throw std::runtime_error("trailing ciphertext bytes");
    return result;
}

static int selftest(const std::string& backend, const std::string& output) {
    std::ofstream out(output);
    if (!out) throw std::runtime_error("cannot open output file");
    auto c = make_context(backend, "S-mul");
    auto a = c.cc->Encrypt(c.keys.publicKey, plain(c, backend, {7}));
    auto b = c.cc->Encrypt(c.keys.publicKey, plain(c, backend, {6}));
    auto result = c.cc->EvalMult(a, b);
    auto encoded = serialize(result);
    auto restored = roundtrip(encoded);
    auto value = backend == "ckks" ? decrypt_approx(c, restored, "S-mul")[0] : decrypt_exact(c, restored, "S-mul")[0];
    if (std::abs(value - 42) > 1e-6) throw std::runtime_error("serialization mismatch");
    bool truncated = false;
    try { auto bad = encoded; bad.pop_back(); (void)roundtrip(bad); } catch (...) { truncated = true; }
    auto other = make_context(backend, "S-mul");
    bool wrong_key = false;
    try {
        auto wrong = backend == "ckks" ? decrypt_approx(other, restored, "S-mul")[0] : decrypt_exact(other, restored, "S-mul")[0];
        wrong_key = std::abs(wrong - 42) > 1e-6;
    } catch (...) { wrong_key = true; }
    if (!truncated || !wrong_key) throw std::runtime_error("negative serialization control failed");
    out << "{\"selftest\":\"PASS\",\"backend\":" << quote(backend)
        << ",\"ct_roundtrip\":true,\"truncated_rejected\":true,\"wrong_key_rejected\":true,"
        << "\"ct_bytes\":" << encoded.size() << "}\n";
    if (!out) throw std::runtime_error("output write failed");
    out.close();
    write_rusage(output);
    return 0;
}

int main(int argc, char** argv) {
    try {
        std::string backend = "bfv", name = "S-add", output;
        int repetitions = 1, warmups = 1, batch = 1, threads = 1, fixture_count = 1;
        for (int i = 1; i < argc; ++i) {
            std::string a = argv[i];
            auto next = [&]() -> std::string { if (++i == argc) throw std::runtime_error("missing argument"); return argv[i]; };
            if (a == "--backend") backend = next();
            else if (a == "--case") name = next();
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
            (batch != 1 && name != "S-add") || (threads != 1 && threads != 4))
            throw std::runtime_error("invalid arguments");
        if (name == "selftest") return selftest(backend, output);
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
        size_t n = (name == "V64" || name == "D64") ? 64 : 1;
        auto c = make_context(backend, name);
        for (int fixture_index = 0; fixture_index < fixture_count; ++fixture_index) {
        auto x = read_vec(), y = read_vec();
        if (x.size() != n) throw std::runtime_error("wrong x shape");
        if ((name == "S-add" || name == "S-mul" || name == "V64" || name == "D64" ||
             name.rfind("CH", 0) == 0) && y.size() != n) throw std::runtime_error("wrong y shape");
        auto encrypted = encrypt(c, backend, name, x, y);
        auto base = std::move(encrypted.first);
        std::vector<double> eval_ms, dec_ms, copy_ms, warmup_eval_ms, warmup_dec_ms;
        std::vector<double> decrypt_batch_ms, output_bytes, output_scales;
        std::vector<uint64_t> output_ciphertext_bytes, batch_output_bytes, output_levels;
        size_t logical = name == "V64" ? 64 : 1;
        size_t count = repetitions * batch * logical;
        std::vector<int64_t> values, warm_exact, e2e_exact;
        std::vector<double> approx, warm_approx, e2e_approx;
        auto append = [&](const CT& ct, std::vector<int64_t>& exact, std::vector<double>& real) {
            if (backend == "ckks") {
                auto v = decrypt_approx(c, ct, name);
                real.insert(real.end(), v.begin(), v.end());
            } else {
                auto v = decrypt_exact(c, ct, name);
                exact.insert(exact.end(), v.begin(), v.end());
            }
        };
        for (int w = 0; w < warmups; ++w) {
            std::vector<CT> input;
            for (const auto& ct : base) input.push_back(ct->Clone());
            auto t0 = Clock::now();
            auto result = evaluate(c, backend, name, input);
            warmup_eval_ms.push_back(ms(t0, Clock::now()));
            auto d0 = Clock::now();
            append(result, warm_exact, warm_approx);
            warmup_dec_ms.push_back(ms(d0, Clock::now()));
        }
        for (int r = 0; r < repetitions; ++r) {
            auto copy_start = Clock::now();
            std::vector<CT> input;
            for (const auto& ct : base) input.push_back(ct->Clone());
            copy_ms.push_back(ms(copy_start, Clock::now()));
            std::vector<CT> results;
            auto t = Clock::now();
            for (int j = 0; j < batch; ++j) results.push_back(evaluate(c, backend, name, input));
            eval_ms.push_back(ms(t, Clock::now()) / batch);
            double batch_dec_ms = 0;
            uint64_t batch_bytes = 0;
            for (const auto& result : results) {
                auto encoded = serialize(result);
                auto restored = roundtrip(encoded);
                auto d = Clock::now();
                append(restored, values, approx);
                batch_dec_ms += ms(d, Clock::now());
                batch_bytes += encoded.size();
                output_ciphertext_bytes.push_back(encoded.size());
                output_levels.push_back(result->GetLevel());
                output_scales.push_back(result->GetScalingFactor());
            }
            dec_ms.push_back(batch_dec_ms / batch);
            decrypt_batch_ms.push_back(batch_dec_ms);
            output_bytes.push_back(static_cast<double>(batch_bytes) / batch);
            batch_output_bytes.push_back(batch_bytes);
        }
        auto e = Clock::now();
        auto fresh = encrypt(c, backend, name, x, y).first;
        auto final = evaluate(c, backend, name, fresh);
        append(final, e2e_exact, e2e_approx);
        double e2e_ms = ms(e, Clock::now());
        uint64_t input_bytes = 0;
        for (const auto& ct : base) input_bytes += serialize(ct).size();
        uint64_t public_bytes = serialize_any(c.keys.publicKey).size();
        uint64_t mult_bytes = 0, rotation_bytes = 0, rotation_key_count = 0;
        if (name != "S-add") {
            for (const auto& key : c.cc->GetEvalMultKeyVector(c.keys.secretKey->GetKeyTag()))
                mult_bytes += serialize_any(key).size();
        }
        if (name == "D64") {
            const auto& rotation_keys = c.cc->GetEvalAutomorphismKeyMap(c.keys.secretKey->GetKeyTag());
            rotation_key_count = rotation_keys.size();
            for (const auto& item : rotation_keys)
                rotation_bytes += serialize_any(item.second).size();
        }
        auto params = Serial::SerializeToString(c.cc);
        out << std::setprecision(17)
            << "{\"backend\":" << quote(backend) << ",\"case\":" << quote(name)
            << ",\"fixture_index\":" << fixture_index << ",\"fixture_count\":" << fixture_count << ","
            << "\"source\":\"b59e1f291965f14fbee5172cd83a20f5b856204f\","
            << "\"encryption_key_model\":\"public_key\",\"fresh_context_per_session\":true,"
            << "\"security_parameter\":\"HEStd_128_classic, library-selected parameters, no independent estimator validation\","
            << "\"serialization\":\"OpenFHE cereal portable binary, uncompressed\","
            << "\"ring_dimension\":" << c.cc->GetRingDimension() << ",\"physical_slots\":" << c.slots
            << ",\"useful_slots\":" << (n == 64 ? 64 : 1)
            << ",\"requested_threads\":" << threads << ",\"observed_threads\":" << observed_threads
            << ",\"parallel_controls_limit\":" << controller_threads
            << ",\"parallel_controls_machine_threads\":" << machine_threads
            << ",\"parameters_json\":";
        if (fixture_index == 0) out << quote(params); else out << "null";
        out << ",\"keygen_ms\":";
        if (fixture_index == 0) out << c.keygen_ms; else out << "null";
        out << ",\"encryption_ms\":" << encrypted.second
            << ",\"e2e_ms\":" << e2e_ms << ",\"batch_size\":" << batch
            << ",\"copy_reset_ms\":" << nums(copy_ms) << ",\"eval_ms\":" << nums(eval_ms)
            << ",\"decrypt_ms\":" << nums(dec_ms) << ",\"decrypt_batch_ms\":" << nums(decrypt_batch_ms)
            << ",\"input_bytes\":" << input_bytes
            << ",\"public_key_bytes\":" << public_bytes << ",\"relinearization_key_bytes\":" << mult_bytes
            << ",\"rotation_key_bytes\":" << rotation_bytes << ",\"rotation_key_count\":" << rotation_key_count
            << ",\"reduction_rotations\":" << (name == "D64" ? 6 : 0)
            << ",\"logical_outputs\":" << logical << ",\"physical_input_ciphertexts\":" << base.size()
            << ",\"output_bytes\":" << nums(output_bytes)
            << ",\"batch_output_bytes\":" << nums(batch_output_bytes)
            << ",\"output_ciphertext_bytes\":" << nums(output_ciphertext_bytes)
            << ",\"output_levels\":" << nums(output_levels) << ",\"output_scales\":" << nums(output_scales)
            << ",\"warmup_eval_ms\":" << nums(warmup_eval_ms) << ",\"warmup_decrypt_ms\":" << nums(warmup_dec_ms)
            << ",\"warmup_values\":" << (backend == "ckks" ? nums(warm_approx) : nums(warm_exact))
            << ",\"values\":" << (backend == "ckks" ? nums(approx) : nums(values))
            << ",\"e2e_values\":" << (backend == "ckks" ? nums(e2e_approx) : nums(e2e_exact))
            << ",\"expected_value_count\":" << count << "}\n";
        }
        if (!out) throw std::runtime_error("output write failed");
        out.close();
        write_rusage(output);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "openfhe_bench: " << e.what() << '\n';
        return 2;
    }
}
