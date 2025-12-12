#ifndef SYSTEM_SOURCE_HPP
#define SYSTEM_SOURCE_HPP

#include "EntropySource.hpp"
#include <fstream>

//
// System True RNG (/dev/random)
// Uses kernel entropy pool from thermal noise, interrupt timing, etc.
// May block if entropy is low (ensures true randomness)
//
class RandomSource final : public EntropySource {
public:
  [[nodiscard]] std::string name() const noexcept override {
    return "Kernel True RNG (/dev/random)";
  }

  [[nodiscard]] bool is_available() noexcept override {
    std::ifstream f("/dev/random", std::ios::binary);
    return f.good();
  }

  [[nodiscard]] std::vector<unsigned char>
  get_entropy(size_t bytes) noexcept override {
    std::vector<unsigned char> result(bytes);
    std::ifstream random_dev("/dev/random", std::ios::binary);

    if (!random_dev) {
      return {};
    }

    random_dev.read(reinterpret_cast<char *>(result.data()),
                    static_cast<std::streamsize>(bytes));
    if (random_dev.gcount() != static_cast<std::streamsize>(bytes)) {
      return {};
    }

    return result;
  }

  [[nodiscard]] int priority() const noexcept override { return 50; }
};

#endif // SYSTEM_SOURCE_HPP
