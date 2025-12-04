#ifndef ENTROPY_MANAGER_HPP
#define ENTROPY_MANAGER_HPP

#include "EntropySource.hpp"
#include <memory>
#include <vector>

class EntropyManager {
private:
  std::vector<std::unique_ptr<EntropySource>> sources;

  // Private constructor for singleton
  EntropyManager();

public:
  // Singleton access
  static EntropyManager &get_instance();

  // Prevent copy/move
  EntropyManager(const EntropyManager &) = delete;
  EntropyManager &operator=(const EntropyManager &) = delete;

  // Get random bytes from the best available source
  std::vector<unsigned char> get_bytes(size_t num_bytes);

  // Get a list of available source names (for debugging/info)
  std::vector<std::string> get_available_sources();
};

#endif // ENTROPY_MANAGER_HPP
