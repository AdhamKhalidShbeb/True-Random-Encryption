#ifndef HARDWARE_SOURCES_HPP
#define HARDWARE_SOURCES_HPP

#include "EntropySource.hpp"
#include <cstring>
#include <fstream>
#include <iostream>

// CPUID detection for RDRAND support
#if defined(_MSC_VER)
#include <intrin.h>
#define TRE_CPUID(leaf, eax, ebx, ecx, edx)                                    \
  do {                                                                         \
    int cpuInfo[4];                                                            \
    __cpuid(cpuInfo, leaf);                                                    \
    eax = cpuInfo[0];                                                          \
    ebx = cpuInfo[1];                                                          \
    ecx = cpuInfo[2];                                                          \
    edx = cpuInfo[3];                                                          \
  } while (0)
#define TRE_HAS_RDRAND()                                                       \
  ([] {                                                                        \
    int cpuInfo[4];                                                            \
    __cpuid(cpuInfo, 1);                                                       \
    return (cpuInfo[2] & (1 << 30)) != 0;                                      \
  }())
#else
#include <cpuid.h>
#define TRE_CPUID(leaf, eax, ebx, ecx, edx)                                    \
  __get_cpuid(leaf, &eax, &ebx, &ecx, &edx)
#define TRE_HAS_RDRAND()                                                       \
  ([] {                                                                        \
    unsigned int eax, ebx, ecx, edx;                                           \
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {                              \
      return (ecx & (1U << 30)) != 0;                                          \
    }                                                                          \
    return false;                                                              \
  }())
#endif

#include <immintrin.h>

// Uses the RDRAND instruction to get entropy directly from CPU thermal noise
class CpuRngSource final : public EntropySource {
public:
  [[nodiscard]] std::string name() const noexcept override {
    return "CPU Hardware RNG (RDRAND)";
  }

  [[nodiscard]] bool is_available() noexcept override {
    return TRE_HAS_RDRAND();
  }

  [[nodiscard]] std::vector<unsigned char>
  get_entropy(size_t bytes) noexcept override {
    std::vector<unsigned char> result;
    result.reserve(bytes);

    while (result.size() < bytes) {
      unsigned long long val = 0;
      bool success = false;

      for (int retries = 0; retries < 10 && !success; ++retries) {
        if (_rdrand64_step(&val))
          success = true;
      }

      if (!success) {
        std::cerr << "RDRAND failed\n";
        return {};
      }

      const auto *bytes_ptr = reinterpret_cast<const unsigned char *>(&val);
      const size_t to_copy = std::min(size_t{8}, bytes - result.size());
      result.insert(result.end(), bytes_ptr, bytes_ptr + to_copy);
    }

    return result;
  }

  [[nodiscard]] int priority() const noexcept override { return 100; }
};

// Linux-only: reads from /dev/hwrng if available
#if defined(__linux__)
class DeviceRngSource final : public EntropySource {
public:
  [[nodiscard]] std::string name() const noexcept override {
    return "Device Hardware RNG (/dev/hwrng)";
  }

  [[nodiscard]] bool is_available() noexcept override {
    std::ifstream f("/dev/hwrng", std::ios::binary);
    return f.good();
  }

  [[nodiscard]] std::vector<unsigned char>
  get_entropy(size_t bytes) noexcept override {
    std::vector<unsigned char> result(bytes);
    std::ifstream f("/dev/hwrng", std::ios::binary);

    if (!f)
      return {};

    f.read(reinterpret_cast<char *>(result.data()),
           static_cast<std::streamsize>(bytes));
    if (f.gcount() != static_cast<std::streamsize>(bytes))
      return {};

    return result;
  }

  [[nodiscard]] int priority() const noexcept override { return 90; }
};
#endif

#endif
