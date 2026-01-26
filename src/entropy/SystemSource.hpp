#ifndef SYSTEM_SOURCE_HPP
#define SYSTEM_SOURCE_HPP

#include "EntropySource.hpp"

#if defined(_WIN32) || defined(_WIN64)
#define TRE_SYS_WINDOWS 1
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <bcrypt.h>
#include <ntstatus.h>
#include <windows.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <fstream>
#endif

// System entropy source - uses BCryptGenRandom on Windows, /dev/random on Unix
class RandomSource final : public EntropySource {
public:
  [[nodiscard]] std::string name() const noexcept override {
#ifdef TRE_SYS_WINDOWS
    return "Windows CNG (BCryptGenRandom)";
#else
    return "Kernel RNG (/dev/random)";
#endif
  }

  [[nodiscard]] bool is_available() noexcept override {
#ifdef TRE_SYS_WINDOWS
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
    NTSTATUS status =
        BCryptGenRandom(NULL, result.data(), static_cast<ULONG>(bytes),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0)
      return {};
#else
    std::ifstream random_dev("/dev/random", std::ios::binary);
    if (!random_dev)
      return {};

    random_dev.read(reinterpret_cast<char *>(result.data()),
                    static_cast<std::streamsize>(bytes));
    if (random_dev.gcount() != static_cast<std::streamsize>(bytes))
      return {};
#endif

    return result;
  }

  [[nodiscard]] int priority() const noexcept override { return 50; }
};

#endif
