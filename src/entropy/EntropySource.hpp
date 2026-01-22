#ifndef ENTROPY_SOURCE_HPP
#define ENTROPY_SOURCE_HPP

#include <string>
#include <vector>

// Base class for entropy sources
class EntropySource {
public:
  virtual ~EntropySource() = default;

  [[nodiscard]] virtual std::string name() const noexcept = 0;
  [[nodiscard]] virtual bool is_available() noexcept = 0;
  [[nodiscard]] virtual std::vector<unsigned char>
  get_entropy(size_t bytes) noexcept = 0;

  // Higher priority sources are preferred (100 = CPU hardware, 50 = system)
  [[nodiscard]] virtual int priority() const noexcept = 0;
};

#endif
