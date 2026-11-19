#include <pvac/pvac.hpp>
#include "pvac_runtime.hpp"
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>

int main(int argc, char** argv) {
    try {
        if (argc != 3 || std::string(argv[1]) != "--output") throw std::runtime_error("usage: --output path");
        std::ofstream out(argv[2]);
        if (!out) throw std::runtime_error("cannot open output file");
        pvac::Params p;
        auto runtime = checked_pvac_kernel();
        out << std::setprecision(17)
            << "{\"B\":" << p.B << ",\"m_bits\":" << p.m_bits << ",\"n_bits\":" << p.n_bits
            << ",\"h_col_wt\":" << p.h_col_wt << ",\"x_col_wt\":" << p.x_col_wt
            << ",\"err_wt\":" << p.err_wt << ",\"noise_entropy_bits\":" << p.noise_entropy_bits
            << ",\"tuple2_fraction\":" << p.tuple2_fraction << ",\"depth_slope_bits\":" << p.depth_slope_bits
            << ",\"edge_budget\":" << p.edge_budget << ",\"lpn_n\":" << p.lpn_n << ",\"lpn_t\":" << p.lpn_t
            << ",\"lpn_tau_num\":" << p.lpn_tau_num << ",\"lpn_tau_den\":" << p.lpn_tau_den
            << ",\"recrypt_lo\":" << p.recrypt_lo << ",\"recrypt_hi\":" << p.recrypt_hi
            << ",\"recrypt_rounds\":" << p.recrypt_rounds
            << ",\"kernel\":\"" << runtime.name << "\",\"runtime_toeplitz_id\":" << runtime.id
            << ",\"kernel_selection_ms\":" << runtime.selection_ms
            << ",\"compiler_flags\":\"" << PVAC_COMPILER_FLAGS << "\","
            << "\"encryption\":\"enc_value wrapped default, depth hint 0\",\"ct_mul_default_width\":8,"
            << "\"ct_square_default_width\":8,\"generator_mode\":\"default keygen public H and UBK\","
            << "\"security_status\":\"concrete whole-construction security unestablished\"}\n";
        if (!out) throw std::runtime_error("output write failed");
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "pvac_parameters: " << e.what() << '\n';
        return 2;
    }
}
