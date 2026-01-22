#include "EntropyManager.hpp"
#include "HardwareSources.hpp"
#include "SystemSource.hpp"
#include <algorithm>
#include <iostream>

EntropyManager::EntropyManager() {
  // Register sources in priority order: RDRAND > hwrng device > system RNG
  sources.push_back(std::make_unique<CpuRngSource>());

#if defined(__linux__)
  sources.push_back(std::make_unique<DeviceRngSource>());
#endif

  sources.push_back(std::make_unique<RandomSource>());

  // Sort by priority so we try the best sources first
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
      std::vector<unsigned char> buffer = source->get_entropy(num_bytes);
      if (!buffer.empty())
        return buffer;
    }
  }

  std::cerr << "All entropy sources failed\n";
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
