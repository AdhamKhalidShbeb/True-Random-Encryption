#ifndef ENTROPY_SOURCE_HPP
#define ENTROPY_SOURCE_HPP

#include <string>
#include <vector>

class EntropySource {
public:
  virtual ~EntropySource() = default;

  // Name of the entropy source (e.g., "Intel RDRAND", "Kernel RNG")
  virtual std::string name() const = 0;

  // Check if this source is available on the current system
  virtual bool is_available() = 0;

  // Get random bytes from this source
  // Returns empty vector on failure
  virtual std::vector<unsigned char> get_entropy(size_t bytes) = 0;

  // Priority of this source (higher is better)
  // 100: Hardware RNG (CPU instructions) - Fastest, high quality
  // 90:  Hardware Device (/dev/hwrng) - Fast, high quality
  // 50:  System RNG (/dev/random) - True randomness (may block)
  virtual int priority() const = 0;
};

#endif // ENTROPY_SOURCE_HPP
