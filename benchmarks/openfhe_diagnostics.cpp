#define main openfhe_harness_main
#include "openfhe_bench.cpp"
#undef main

#include <functional>

static std::string measure(const Context& c, const std::string& backend, const std::string& label,
                           const std::vector<CT>& base, const std::function<CT(std::vector<CT>&)>& operation) {
    std::vector<double> timings;
    CT result;
    for (int i = 0; i < 5; ++i) {
        std::vector<CT> input;
        for (const auto& ct : base) input.push_back(ct->Clone());
        auto start = Clock::now();
        CT next = operation(input);
        timings.push_back(ms(start, Clock::now()));
        result = std::move(next);
        double value = backend == "ckks" ? decrypt_approx(c, result, "S-mul")[0] : decrypt_exact(c, result, "S-mul")[0];
        if (std::abs(value - 42) > 1e-6) throw std::runtime_error(label + ": incorrect result");
    }
    return "{" + std::string("\"samples_ms\":") + nums(timings) +
           ",\"input_ciphertext_elements\":" + std::to_string(base[0]->NumberCiphertextElements()) +
           ",\"input_level\":" + std::to_string(base[0]->GetLevel()) +
           ",\"input_scale\":" + std::to_string(base[0]->GetScalingFactor()) +
           ",\"ciphertext_elements\":" + std::to_string(result->NumberCiphertextElements()) +
           ",\"level\":" + std::to_string(result->GetLevel()) +
           ",\"scale\":" + std::to_string(result->GetScalingFactor()) + "}";
}

static std::string diagnostic(const std::string& backend, const std::string& context_case) {
    auto c = make_context(backend, context_case);
    auto a = c.cc->Encrypt(c.keys.publicKey, plain(c, backend, {7}));
    auto b = c.cc->Encrypt(c.keys.publicKey, plain(c, backend, {6}));
    auto raw = c.cc->EvalMultNoRelin(a, b);
    const auto& cc = c.cc;
    std::vector<std::pair<std::string, std::string>> entries;
    entries.push_back({"EvalMultNoRelin", measure(c, backend, "raw", {a, b}, [&](std::vector<CT>& v) {
        return cc->EvalMultNoRelin(v[0], v[1]);
    })});
    entries.push_back({"EvalMult", measure(c, backend, "normal", {a, b}, [&](std::vector<CT>& v) {
        return cc->EvalMult(v[0], v[1]);
    })});
    entries.push_back({"Relinearize", measure(c, backend, "relinearize", {raw}, [&](std::vector<CT>& v) {
        return cc->Relinearize(v[0]);
    })});
    auto relin = cc->Relinearize(raw);
    if (backend == "ckks") {
        entries.push_back({"Rescale", measure(c, backend, "rescale", {relin}, [&](std::vector<CT>& v) {
            auto result = v[0];
            cc->RescaleInPlace(result);
            return result;
        })});
    } else {
        entries.push_back({"Rescale", "{\"status\":\"N/A_noop_under_selected_policy\"}"});
    }
    entries.push_back({"application_output", measure(c, backend, "application", {a, b}, [&](std::vector<CT>& v) {
        return ct_mul(c, backend, v[0], v[1]);
    })});
    std::ostringstream out;
    out << "{\"backend\":" << quote(backend) << ",\"context_case\":" << quote(context_case)
        << ",\"ring_dimension\":" << c.cc->GetRingDimension()
        << ",\"parameters_json\":" << quote(Serial::SerializeToString(c.cc)) << ",\"operations\":{";
    for (size_t i = 0; i < entries.size(); ++i) {
        if (i) out << ',';
        out << quote(entries[i].first) << ':' << entries[i].second;
    }
    out << "}}";
    return out.str();
}

int main(int argc, char** argv) {
    try {
        if (argc != 3 || std::string(argv[1]) != "--output") throw std::runtime_error("usage: --output path");
        std::ofstream out(argv[2]);
        if (!out) throw std::runtime_error("cannot open output file");
        out << "{\"diagnostic_scope\":\"native OpenFHE operation scopes, not equivalent-task rankings\","
            << "\"results\":[";
        bool first = true;
        for (const std::string& backend : {"bfv", "bgv", "ckks"}) {
            for (const std::string& context_case : {"S-mul", "CH5"}) {
                if (!first) out << ',';
                first = false;
                out << diagnostic(backend, context_case);
            }
        }
        out << "]}\n";
        if (!out) throw std::runtime_error("output write failed");
        out.close();
        write_rusage(argv[2]);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "openfhe_diagnostics: " << e.what() << '\n';
        return 2;
    }
}
