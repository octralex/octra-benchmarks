#pragma once

#include <pvac/pvac.hpp>

#include <chrono>
#include <stdexcept>
#include <string>

struct PvacRuntimeKernel {
    int id;
    std::string name;
    double selection_ms;
};

inline PvacRuntimeKernel checked_pvac_kernel() {
    auto start = std::chrono::steady_clock::now();
    pvac::select_toeplitz();
    double selection_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
    std::string name;
    if (pvac::g_toep_id == 1) name = "gf2_conv_clmul";
    else if (pvac::g_toep_id == 2) name = "gf2_conv_pmull";
    else if (pvac::g_toep_id == 3) name = "gf2_conv_scalar";
    else throw std::runtime_error("unknown PVAC Toeplitz dispatch");
    if (pvac::g_toep_id == 3 || !pvac::g_toep) throw std::runtime_error("PVAC scalar Toeplitz dispatch rejected");
#if defined(__PCLMUL__)
    if (pvac::g_toep_id == 1 && pvac::g_toep != &pvac::toep_127_clmul)
        throw std::runtime_error("PVAC dispatch identity mismatch");
#endif
#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
    if (pvac::g_toep_id == 2 && pvac::g_toep != &pvac::toep_127_pmull)
        throw std::runtime_error("PVAC dispatch identity mismatch");
#endif
    return {pvac::g_toep_id, name, selection_ms};
}
