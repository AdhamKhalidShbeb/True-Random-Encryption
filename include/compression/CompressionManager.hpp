#pragma once

#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sodium.h>
#include <string>
#include <vector>
#include <zstd.h>

//
// COMPRESSION MANAGER
// Handles data compression/decompression using Zstandard (zstd)
//

namespace QRE {

// Compression levels
enum class CompressionLevel : uint8_t {
  NONE = 0,     // No compression
  FAST = 1,     // Fast compression (zstd level 1) - 25% compression, 75% speed
  BALANCED = 2, // Balanced (zstd level 6) - 50% compression, 50% speed
  MAX = 3,  // Maximum compression (zstd level 15) - 75% compression, 25% speed
  ULTRA = 4 // Ultra compression (zstd level 22) - Maximum compression
};

// Convert compression level to zstd compression level
inline int compression_level_to_zstd(CompressionLevel level) {
  switch (level) {
  case CompressionLevel::NONE:
    return 0;
  case CompressionLevel::FAST:
    return 1; // Fastest
  case CompressionLevel::BALANCED:
    return 6; // Default zstd level (good balance)
  case CompressionLevel::MAX:
    return 15; // High compression
  case CompressionLevel::ULTRA:
    return 22; // Maximum compression (ZSTD_maxCLevel())
  default:
    return 0;
  }
}

// Get human-readable name for compression level
inline std::string compression_level_name(CompressionLevel level) {
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
// Returns compressed data or empty vector on failure
inline std::vector<unsigned char>
compress_data(const std::vector<unsigned char> &input, CompressionLevel level,
              bool verbose = false) {
  if (level == CompressionLevel::NONE || input.empty()) {
    return input; // No compression or empty input
  }

  int zstd_level = compression_level_to_zstd(level);

  if (verbose) {
    std::cout << "[DEBUG] Compressing " << input.size()
              << " bytes with level: " << compression_level_name(level)
              << " (zstd level " << zstd_level << ")..." << std::endl;
  }

  // Get maximum compressed size (worst case)
  size_t max_compressed_size = ZSTD_compressBound(input.size());

  // Allocate output buffer
  std::vector<unsigned char> compressed(max_compressed_size);

  // Compress
  size_t compressed_size =
      ZSTD_compress(compressed.data(), max_compressed_size, input.data(),
                    input.size(), zstd_level);

  // Check for errors
  if (ZSTD_isError(compressed_size)) {
    std::cerr << "Compression error: " << ZSTD_getErrorName(compressed_size)
              << std::endl;
    return {}; // Return empty vector on error
  }

  // Resize to actual compressed size
  compressed.resize(compressed_size);

  // Calculate and report compression ratio
  if (verbose || input.size() > 1024 * 1024) { // Always show for large files
    double ratio = 100.0 * (1.0 - (double)compressed_size / input.size());
    std::cout << "✓ Compression: " << input.size() << " → " << compressed_size
              << " bytes (" << std::fixed << std::setprecision(1) << ratio
              << "% reduction)" << std::endl;
  }

  return compressed;
}

// Decompress data using zstd
// Returns decompressed data or empty vector on failure
inline std::vector<unsigned char>
decompress_data(const std::vector<unsigned char> &compressed,
                bool verbose = false) {
  if (compressed.empty()) {
    return {}; // Empty input
  }

  // Get the decompressed size (stored in the frame header)
  unsigned long long decompressed_size =
      ZSTD_getFrameContentSize(compressed.data(), compressed.size());

  // Check for errors
  if (decompressed_size == ZSTD_CONTENTSIZE_ERROR) {
    std::cerr << "Decompression error: Not a valid zstd frame" << std::endl;
    return {};
  }
  if (decompressed_size == ZSTD_CONTENTSIZE_UNKNOWN) {
    std::cerr << "Decompression error: Original size unknown" << std::endl;
    return {};
  }

  if (verbose) {
    std::cout << "[DEBUG] Decompressing " << compressed.size() << " bytes to "
              << decompressed_size << " bytes..." << std::endl;
  }

  // Allocate output buffer
  std::vector<unsigned char> decompressed(decompressed_size);

  // Decompress
  size_t result = ZSTD_decompress(decompressed.data(), decompressed_size,
                                  compressed.data(), compressed.size());

  // Check for errors
  if (ZSTD_isError(result)) {
    std::cerr << "Decompression error: " << ZSTD_getErrorName(result)
              << std::endl;
    // Securely wipe buffer before returning
    sodium_memzero(decompressed.data(), decompressed.size());
    return {};
  }

  if (verbose) {
    std::cout << "✓ Decompressed successfully" << std::endl;
  }

  return decompressed;
}

// Self-test for compression round-trip
inline bool compression_self_test(bool verbose = false) {
  if (verbose) {
    std::cout << "[DEBUG] Running compression self-tests..." << std::endl;
  }

  // Test data with repetitive pattern (should compress well)
  std::vector<unsigned char> test_data;
  std::string pattern = "This is a test pattern for compression. ";
  for (int i = 0; i < 100; i++) {
    test_data.insert(test_data.end(), pattern.begin(), pattern.end());
  }

  // Test each compression level
  CompressionLevel levels[] = {CompressionLevel::FAST,
                               CompressionLevel::BALANCED,
                               CompressionLevel::MAX, CompressionLevel::ULTRA};

  for (auto level : levels) {
    // Compress
    std::vector<unsigned char> compressed =
        compress_data(test_data, level, verbose);
    if (compressed.empty()) {
      std::cerr << "Self-test FAILED: Compression failed for level "
                << compression_level_name(level) << std::endl;
      return false;
    }

    // Decompress
    std::vector<unsigned char> decompressed =
        decompress_data(compressed, verbose);
    if (decompressed.empty()) {
      std::cerr << "Self-test FAILED: Decompression failed for level "
                << compression_level_name(level) << std::endl;
      return false;
    }

    // Verify round-trip
    if (decompressed != test_data) {
      std::cerr << "Self-test FAILED: Round-trip mismatch for level "
                << compression_level_name(level) << std::endl;
      return false;
    }

    if (verbose) {
      std::cout << "✓ Compression level " << compression_level_name(level)
                << " test passed" << std::endl;
    }
  }

  if (verbose) {
    std::cout << "✓ All compression self-tests passed!" << std::endl;
  }

  return true;
}

} // namespace QRE
