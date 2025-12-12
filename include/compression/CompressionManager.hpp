#pragma once

#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sodium.h>
#include <string>
#include <string_view>
#include <vector>
#include <zstd.h>

namespace QRE {

// Compression levels
enum class CompressionLevel : uint8_t {
  NONE = 0,     // No compression
  FAST = 1,     // Fast compression (zstd level 1)
  BALANCED = 2, // Balanced (zstd level 6)
  MAX = 3,      // Maximum compression (zstd level 15)
  ULTRA = 4     // Ultra compression (zstd level 22)
};

// Convert compression level to zstd compression level
[[nodiscard]] constexpr int
compression_level_to_zstd(CompressionLevel level) noexcept {
  switch (level) {
  case CompressionLevel::NONE:
    return 0;
  case CompressionLevel::FAST:
    return 1;
  case CompressionLevel::BALANCED:
    return 6;
  case CompressionLevel::MAX:
    return 15;
  case CompressionLevel::ULTRA:
    return 22;
  default:
    return 0;
  }
}

// Get human-readable name for compression level
[[nodiscard]] constexpr std::string_view
compression_level_name(CompressionLevel level) noexcept {
  switch (level) {
  case CompressionLevel::NONE:
    return "None";
  case CompressionLevel::FAST:
    return "Fast";
  case CompressionLevel::BALANCED:
    return "Balanced";
  case CompressionLevel::MAX:
    return "Maximum";
  case CompressionLevel::ULTRA:
    return "Ultra";
  default:
    return "Unknown";
  }
}

// Compress data using zstd
[[nodiscard]] inline std::vector<unsigned char>
compress_data(const std::vector<unsigned char> &input, CompressionLevel level,
              bool verbose = false) {
  if (level == CompressionLevel::NONE || input.empty()) {
    return input;
  }

  const int zstd_level = compression_level_to_zstd(level);

  if (verbose) {
    std::cout << "[DEBUG] Compressing " << input.size()
              << " bytes with level: " << compression_level_name(level)
              << " (zstd level " << zstd_level << ")...\n";
  }

  const size_t max_compressed_size = ZSTD_compressBound(input.size());
  std::vector<unsigned char> compressed(max_compressed_size);

  const size_t compressed_size =
      ZSTD_compress(compressed.data(), max_compressed_size, input.data(),
                    input.size(), zstd_level);

  if (ZSTD_isError(compressed_size)) {
    std::cerr << "Compression error: " << ZSTD_getErrorName(compressed_size)
              << '\n';
    return {};
  }

  compressed.resize(compressed_size);

  // Report compression ratio for large files or in verbose mode
  if (verbose || input.size() > 1024 * 1024) {
    const double ratio = 100.0 * (1.0 - static_cast<double>(compressed_size) /
                                            static_cast<double>(input.size()));
    std::cout << "✓ Compression: " << input.size() << " → " << compressed_size
              << " bytes (" << std::fixed << std::setprecision(1) << ratio
              << "% reduction)\n";
  }

  return compressed;
}

// Decompress data using zstd
[[nodiscard]] inline std::vector<unsigned char>
decompress_data(const std::vector<unsigned char> &compressed,
                bool verbose = false) {
  if (compressed.empty()) {
    return {};
  }

  const unsigned long long decompressed_size =
      ZSTD_getFrameContentSize(compressed.data(), compressed.size());

  if (decompressed_size == ZSTD_CONTENTSIZE_ERROR) {
    std::cerr << "Decompression error: Not a valid zstd frame\n";
    return {};
  }
  if (decompressed_size == ZSTD_CONTENTSIZE_UNKNOWN) {
    std::cerr << "Decompression error: Original size unknown\n";
    return {};
  }

  // Security: Limit maximum decompressed size to prevent decompression bombs
  constexpr size_t MAX_DECOMPRESSED_SIZE = 1024ULL * 1024 * 1024; // 1 GB
  if (decompressed_size > MAX_DECOMPRESSED_SIZE) {
    std::cerr << "Decompression error: Decompressed size exceeds limit ("
              << decompressed_size << " > " << MAX_DECOMPRESSED_SIZE << ")\n";
    return {};
  }

  if (verbose) {
    std::cout << "[DEBUG] Decompressing " << compressed.size() << " bytes to "
              << decompressed_size << " bytes...\n";
  }

  std::vector<unsigned char> decompressed(decompressed_size);

  const size_t result = ZSTD_decompress(decompressed.data(), decompressed_size,
                                        compressed.data(), compressed.size());

  if (ZSTD_isError(result)) {
    std::cerr << "Decompression error: " << ZSTD_getErrorName(result) << '\n';
    sodium_memzero(decompressed.data(), decompressed.size());
    return {};
  }

  if (verbose) {
    std::cout << "✓ Decompressed successfully\n";
  }

  return decompressed;
}

// Self-test for compression round-trip
[[nodiscard]] inline bool compression_self_test(bool verbose = false) {
  if (verbose) {
    std::cout << "[DEBUG] Running compression self-tests...\n";
  }

  // Create test data with repetitive pattern
  std::vector<unsigned char> test_data;
  constexpr std::string_view pattern =
      "This is a test pattern for compression. ";
  test_data.reserve(pattern.size() * 100);
  for (int i = 0; i < 100; ++i) {
    test_data.insert(test_data.end(), pattern.begin(), pattern.end());
  }

  // Test each compression level
  constexpr CompressionLevel levels[] = {
      CompressionLevel::FAST, CompressionLevel::BALANCED, CompressionLevel::MAX,
      CompressionLevel::ULTRA};

  for (const auto level : levels) {
    auto compressed = compress_data(test_data, level, verbose);
    if (compressed.empty()) {
      std::cerr << "Self-test FAILED: Compression failed for level "
                << compression_level_name(level) << '\n';
      return false;
    }

    auto decompressed = decompress_data(compressed, verbose);
    if (decompressed.empty()) {
      std::cerr << "Self-test FAILED: Decompression failed for level "
                << compression_level_name(level) << '\n';
      return false;
    }

    if (decompressed != test_data) {
      std::cerr << "Self-test FAILED: Round-trip mismatch for level "
                << compression_level_name(level) << '\n';
      return false;
    }

    if (verbose) {
      std::cout << "✓ Compression level " << compression_level_name(level)
                << " test passed\n";
    }
  }

  if (verbose) {
    std::cout << "✓ All compression self-tests passed!\n";
  }

  return true;
}

} // namespace QRE
