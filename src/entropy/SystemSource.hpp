#ifndef SYSTEM_SOURCE_HPP
#define SYSTEM_SOURCE_HPP

#include "EntropySource.hpp"

// Platform detection
#if defined(_WIN32) || defined(_WIN64)
#define TRE_SYS_WINDOWS 1
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <bcrypt.h>
#include <windows.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <fstream>
#endif

//
// System True RNG
// Linux/macOS: Uses /dev/random (kernel entropy pool from thermal noise,
//              interrupt timing, hardware events)
// Windows: Uses BCryptGenRandom (TPM, RDRAND, system entropy pool)
//
class RandomSource final : public EntropySource {
public:
  [[nodiscard]] std::string name() const noexcept override {
#ifdef TRE_SYS_WINDOWS
    return "Windows CNG (BCryptGenRandom)";
#else
    return "Kernel True RNG (/dev/random)";
#endif
  }

  [[nodiscard]] bool is_available() noexcept override {
#ifdef TRE_SYS_WINDOWS
    // BCryptGenRandom is always available on modern Windows
    return true;
#else
    std::ifstream f("/dev/random", std::ios::binary);
    return f.good();
#endif
  }

  [[nodiscard]] std::vector<unsigned char>
  get_entropy(size_t bytes) noexcept override {
    std::vector<unsigned char> result(bytes);

#ifdef TRE_SYS_WINDOWS
    // Use Windows CNG API with system-preferred RNG
    // This pulls from TPM, RDRAND, and system entropy pool
    NTSTATUS status =
        BCryptGenRandom(NULL, result.data(), static_cast<ULONG>(bytes),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) { // STATUS_SUCCESS = 0
      return {};
    }
#else
    // Use /dev/random for true hardware randomness on Linux/macOS
    std::ifstream random_dev("/dev/random", std::ios::binary);
    if (!random_dev) {
      return {};
    }

    random_dev.read(reinterpret_cast<char *>(result.data()),
                    static_cast<std::streamsize>(bytes));
    if (random_dev.gcount() != static_cast<std::streamsize>(bytes)) {
      return {};
    }
#endif

    return result;
  }

  [[nodiscard]] int priority() const noexcept override { return 50; }
};

#endif // SYSTEM_SOURCE_HPP
