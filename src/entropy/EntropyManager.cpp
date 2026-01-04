#include "EntropyManager.hpp"
#include "HardwareSources.hpp"
#include "SystemSource.hpp"
#include <algorithm>
#include <iostream>

EntropyManager::EntropyManager() {
  // Register all known sources (offline-only, true randomness only)
  // Priority order: CPU RDRAND (100) > Device HW RNG (90) > System RNG (50)
  sources.push_back(std::make_unique<CpuRngSource>());

#if defined(__linux__)
  // /dev/hwrng is only available on Linux
  sources.push_back(std::make_unique<DeviceRngSource>());
#endif

  sources.push_back(std::make_unique<RandomSource>());

  // Sort by priority (descending)
  std::sort(sources.begin(), sources.end(),
            [](const std::unique_ptr<EntropySource> &a,
               const std::unique_ptr<EntropySource> &b) {
              return a->priority() > b->priority();
            });
}

EntropyManager &EntropyManager::get_instance() {
  static EntropyManager instance;
  return instance;
}

std::vector<unsigned char> EntropyManager::get_bytes(size_t num_bytes) {
  for (const auto &source : sources) {
    if (source->is_available()) {
      // Try to get entropy
      std::vector<unsigned char> buffer = source->get_entropy(num_bytes);

      if (!buffer.empty()) {
        // Success!
        // Only log if verbose (we don't have access to global VERBOSE here
        // easily, but we can add a method or just keep it silent for now)
        return buffer;
      }
      // If empty, source failed (e.g. hardware unavailable), try next one
    }
  }

  // If all failed (should never happen due to /dev/random), return empty
  std::cerr << "CRITICAL ERROR: All entropy sources failed!" << std::endl;
  return {};
}

std::vector<std::string> EntropyManager::get_available_sources() {
  std::vector<std::string> names;
  for (const auto &source : sources) {
    if (source->is_available()) {
      names.push_back(source->name());
    }
  }
  return names;
}
