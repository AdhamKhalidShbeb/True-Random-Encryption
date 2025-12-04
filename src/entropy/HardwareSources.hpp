#ifndef HARDWARE_SOURCES_HPP
#define HARDWARE_SOURCES_HPP

#include "EntropySource.hpp"
#include <cpuid.h>
#include <fstream>
#include <immintrin.h>
#include <iostream>

//
// CPU Hardware RNG (RDRAND/RDSEED)
//
class CpuRngSource : public EntropySource {
public:
  std::string name() const override {
    return "CPU Hardware RNG (RDRAND/RDSEED)";
  }

  bool is_available() override {
    unsigned int eax, ebx, ecx, edx;
    // Check for RDRAND support (Leaf 1, ECX bit 30)
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
      return (ecx & (1 << 30)) != 0;
    }
    return false;
  }

  std::vector<unsigned char> get_entropy(size_t bytes) override {
    std::vector<unsigned char> result;
    result.reserve(bytes);

    size_t bytes_generated = 0;
    while (bytes_generated < bytes) {
      unsigned long long val;
      int retries = 0;
      const int MAX_RETRIES = 10;
      int success = 0;

      // Try RDSEED first (better entropy), fallback to RDRAND
      while (retries < MAX_RETRIES && !success) {
        // _rdseed64_step returns 1 on success
        // Note: We use __builtin_ia32_rdseed64_step if available, or inline asm
        // if needed For simplicity and portability with -mrdrnd, we'll try
        // RDRAND which is more widely available and stable than RDSEED (which
        // can underflow). Ideally we would check for RDSEED support separately.
        // For this implementation, we will stick to RDRAND as the primary
        // stable source.

        if (_rdrand64_step(&val)) {
          success = 1;
        } else {
          retries++;
        }
      }

      if (!success) {
        // Hardware failure or busy
        std::cerr << "Warning: RDRAND failed after retries" << std::endl;
        return {}; // Return empty to trigger fallback
      }

      // Append bytes
      unsigned char *p = reinterpret_cast<unsigned char *>(&val);
      for (size_t i = 0; i < 8 && bytes_generated < bytes; ++i) {
        result.push_back(p[i]);
        bytes_generated++;
      }
    }

    return result;
  }

  int priority() const override {
    return 100; // Highest priority
  }
};

//
// Device Hardware RNG (/dev/hwrng)
//
class DeviceRngSource : public EntropySource {
public:
  std::string name() const override {
    return "Device Hardware RNG (/dev/hwrng)";
  }

  bool is_available() override {
    std::ifstream f("/dev/hwrng", std::ios::binary);
    return f.good();
  }

  std::vector<unsigned char> get_entropy(size_t bytes) override {
    std::vector<unsigned char> result(bytes);
    std::ifstream f("/dev/hwrng", std::ios::binary);

    if (!f)
      return {};

    f.read(reinterpret_cast<char *>(result.data()), bytes);
    if (f.gcount() != static_cast<std::streamsize>(bytes)) {
      return {}; // Partial read or error
    }

    return result;
  }

  int priority() const override {
    return 90; // High priority, but prefer CPU instruction if available
               // (faster)
  }
};

#endif // HARDWARE_SOURCES_HPP
