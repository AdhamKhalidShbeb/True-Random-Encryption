#ifndef SYSTEM_SOURCE_HPP
#define SYSTEM_SOURCE_HPP

#include "EntropySource.hpp"
#include <fstream>
#include <iostream>

//
// System True RNG (/dev/random)
// Uses kernel entropy pool from thermal noise, interrupt timing, etc.
// May block if entropy is low (ensures true randomness)
//
class RandomSource : public EntropySource {
public:
  std::string name() const override { return "Kernel True RNG (/dev/random)"; }

  bool is_available() override {
    std::ifstream f("/dev/random", std::ios::binary);
    return f.good();
  }

  std::vector<unsigned char> get_entropy(size_t bytes) override {
    std::vector<unsigned char> result(bytes);
    std::ifstream random_dev("/dev/random", std::ios::binary);

    if (!random_dev)
      return {};

    random_dev.read(reinterpret_cast<char *>(result.data()), bytes);
    if (random_dev.gcount() != static_cast<std::streamsize>(bytes)) {
      return {}; // Partial read
    }

    return result;
  }

  int priority() const override {
    return 50; // Lowest priority (fallback), but still true randomness
  }
};

#endif // SYSTEM_SOURCE_HPP
