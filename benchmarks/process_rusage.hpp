#pragma once

#include <cstdint>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>
#include <sys/resource.h>

inline void write_rusage(const std::string& output) {
    rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage) != 0 || usage.ru_maxrss <= 0)
        throw std::runtime_error("getrusage failed");
#if defined(__APPLE__)
    constexpr uint64_t multiplier = 1;
    const char* raw_unit = "bytes";
    const char* unit = "bytes (macOS getrusage RUSAGE_SELF)";
#elif defined(__linux__)
    constexpr uint64_t multiplier = 1024;
    const char* raw_unit = "KiB";
    const char* unit = "bytes (Linux getrusage RUSAGE_SELF, ru_maxrss KiB converted to bytes)";
#else
#error "unsupported getrusage platform"
#endif
    const auto raw = static_cast<uint64_t>(usage.ru_maxrss);
    if (raw > std::numeric_limits<uint64_t>::max() / multiplier)
        throw std::runtime_error("getrusage overflow");
    const uint64_t bytes = raw * multiplier;
    std::ofstream out(output + ".rusage.json");
    if (!out) throw std::runtime_error("cannot open rusage output");
    out << "{\"process_peak_rss_bytes\":" << bytes
        << ",\"process_peak_rss_raw\":" << raw
        << ",\"process_peak_rss_raw_unit\":\"" << raw_unit << "\""
        << ",\"process_peak_rss_unit\":\"" << unit << "\""
        << ",\"process_peak_rss_source\":\"adapter_exit\","
        << "\"scope\":\"whole process including setup, validation and serialization, not eval-only allocation\"}\n";
    if (!out) throw std::runtime_error("rusage output write failed");
}
