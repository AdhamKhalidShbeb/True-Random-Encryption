#ifndef ENTROPY_MANAGER_HPP
#define ENTROPY_MANAGER_HPP

#include "EntropySource.hpp"
#include <memory>
#include <vector>

// Manages all available entropy sources and picks the best one
class EntropyManager {
private:
  std::vector<std::unique_ptr<EntropySource>> sources;
  EntropyManager();

public:
  static EntropyManager &get_instance();

  EntropyManager(const EntropyManager &) = delete;
  EntropyManager &operator=(const EntropyManager &) = delete;

  std::vector<unsigned char> get_bytes(size_t num_bytes);
  std::vector<std::string> get_available_sources();
};

#endif
