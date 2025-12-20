#include "CryptoCore.hpp"
#include "password_blacklist.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace TRE {

//
// SECURE MEMORY UTILITIES
//

void secure_wipe_string(std::string &s) noexcept {
  if (!s.empty()) {
    sodium_memzero(s.data(), s.size());
    s.clear();
  }
}

void secure_wipe_vector(std::vector<unsigned char> &v) noexcept {
  if (!v.empty()) {
    sodium_memzero(v.data(), v.size());
    v.clear();
  }
}

bool secure_delete_file(const std::string &filename) {
  const int fd = open(filename.c_str(), O_RDWR | O_NOFOLLOW);
  if (fd < 0) {
    return false;
  }

  struct stat file_stat{};
  if (fstat(fd, &file_stat) != 0) {
    close(fd);
    return false;
  }
  const auto filesize = static_cast<size_t>(file_stat.st_size);

  if (filesize > 0) {
    // Seek to beginning before overwriting
    if (lseek(fd, 0, SEEK_SET) < 0) {
      close(fd);
      return false;
    }

    constexpr size_t CHUNK_SIZE = 1024 * 1024;
    std::vector<unsigned char> zeros(std::min(filesize, CHUNK_SIZE), 0);
    size_t written = 0;

    while (written < filesize) {
      const size_t to_write = std::min(zeros.size(), filesize - written);
      const ssize_t result = write(fd, zeros.data(), to_write);
      if (result < 0) {
        close(fd);
        return false;
      }
      written += static_cast<size_t>(result);
    }
    fsync(fd);
  }

  close(fd);
  return remove(filename.c_str()) == 0;
}

bool is_safe_path(const std::string &path) {
  // Reject paths with directory traversal
  if (path.find("..") != std::string::npos) {
    return false;
  }

  // Reject absolute paths
  if (!path.empty() && path[0] == '/') {
    return false;
  }

  // Use std::filesystem for path resolution
  try {
    const auto cwd = fs::current_path();
    const auto resolved = fs::weakly_canonical(path);

    // Check if resolved path is within cwd
    auto [cwd_end, resolved_it] =
        std::mismatch(cwd.begin(), cwd.end(), resolved.begin(), resolved.end());

    return cwd_end == cwd.end();
  } catch (const fs::filesystem_error &) {
    return false;
  }
}

//
// SECURE PASSWORD CLASS
//

SecurePassword::SecurePassword(size_t max_len)
    : data_(new char[max_len]), capacity_(max_len), length_(0) {
  std::memset(data_, 0, capacity_);
  // Attempt to lock memory (prevent swapping)
  if (mlock(data_, capacity_) != 0) {
    // Non-fatal: memory locking may fail without root privileges
    // Password is still secure, just potentially swappable
  }
}

SecurePassword::~SecurePassword() {
  if (data_) {
    sodium_memzero(data_, capacity_);
    munlock(data_, capacity_);
    delete[] data_;
  }
}

SecurePassword::SecurePassword(SecurePassword &&other) noexcept
    : data_(other.data_), capacity_(other.capacity_), length_(other.length_) {
  other.data_ = nullptr;
  other.capacity_ = 0;
  other.length_ = 0;
}

SecurePassword &SecurePassword::operator=(SecurePassword &&other) noexcept {
  if (this != &other) {
    // Clean up existing data
    if (data_) {
      sodium_memzero(data_, capacity_);
      munlock(data_, capacity_);
      delete[] data_;
    }

    // Move from other
    data_ = other.data_;
    capacity_ = other.capacity_;
    length_ = other.length_;

    other.data_ = nullptr;
    other.capacity_ = 0;
    other.length_ = 0;
  }
  return *this;
}

void SecurePassword::set(const char *input, size_t len) {
  if (len >= capacity_) {
    len = capacity_ - 1;
  }
  length_ = len;
  std::memcpy(data_, input, len);
  data_[len] = '\0';
}

//
// CRYPTOGRAPHIC FUNCTIONS
//

std::vector<unsigned char> derive_key(const char *password, size_t password_len,
                                      const std::vector<unsigned char> &salt) {
  if (password == nullptr || password_len == 0 || salt.size() != SALT_SIZE) {
    std::exit(1);
  }

  std::vector<unsigned char> key(KEY_SIZE);
  const bool key_locked = (mlock(key.data(), KEY_SIZE) == 0);

  // Argon2id parameters: 64MB memory, 3 iterations
  constexpr unsigned long long ARGON2_MEMORY = 64ULL * 1024 * 1024;
  constexpr unsigned long long ARGON2_OPS = 3;

  if (crypto_pwhash(key.data(), KEY_SIZE, password, password_len, salt.data(),
                    ARGON2_OPS, ARGON2_MEMORY,
                    crypto_pwhash_ALG_ARGON2ID13) != 0) {
    sodium_memzero(key.data(), KEY_SIZE);
    if (key_locked) {
      munlock(key.data(), KEY_SIZE);
    }
    std::exit(1);
  }

  return key;
}

std::vector<unsigned char>
encrypt_aes256gcm(const std::vector<unsigned char> &plaintext,
                  const std::vector<unsigned char> &key,
                  const std::vector<unsigned char> &nonce) {
  if (key.size() != KEY_SIZE || nonce.size() != NONCE_SIZE) {
    std::exit(1);
  }
  if (!crypto_aead_aes256gcm_is_available()) {
    std::exit(1);
  }

  std::vector<unsigned char> ciphertext(plaintext.size() +
                                        crypto_aead_aes256gcm_ABYTES);
  unsigned long long ciphertext_len = 0;

  crypto_aead_aes256gcm_encrypt(ciphertext.data(), &ciphertext_len,
                                plaintext.data(), plaintext.size(), nullptr, 0,
                                nullptr, nonce.data(), key.data());

  ciphertext.resize(ciphertext_len);
  return ciphertext;
}

std::vector<unsigned char>
decrypt_aes256gcm(const std::vector<unsigned char> &ciphertext,
                  const std::vector<unsigned char> &key,
                  const std::vector<unsigned char> &nonce) {
  if (key.size() != KEY_SIZE || nonce.size() != NONCE_SIZE) {
    return {};
  }
  if (!crypto_aead_aes256gcm_is_available()) {
    std::exit(1);
  }
  if (ciphertext.size() < crypto_aead_aes256gcm_ABYTES) {
    return {};
  }

  std::vector<unsigned char> plaintext(ciphertext.size() -
                                       crypto_aead_aes256gcm_ABYTES);
  unsigned long long plaintext_len = 0;

  if (crypto_aead_aes256gcm_decrypt(
          plaintext.data(), &plaintext_len, nullptr, ciphertext.data(),
          ciphertext.size(), nullptr, 0, nonce.data(), key.data()) != 0) {
    return {};
  }

  plaintext.resize(plaintext_len);
  return plaintext;
}

//
// VALIDATION
//

bool validate_password(std::string_view password, std::string &error_msg) {
  // Check against blacklist (case-insensitive)
  std::string password_lower(password);
  std::transform(password_lower.begin(), password_lower.end(),
                 password_lower.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  // Search blacklist by converting each entry to lowercase
  for (const auto &blacklisted : PASSWORD_BLACKLIST) {
    std::string blacklisted_lower = blacklisted;
    std::transform(blacklisted_lower.begin(), blacklisted_lower.end(),
                   blacklisted_lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (password_lower == blacklisted_lower) {
      error_msg = "This password is too common and easily guessable.";
      return false;
    }
  }

  if (password.length() < MIN_PASSWORD_LENGTH) {
    error_msg = "Password must be at least " +
                std::to_string(MIN_PASSWORD_LENGTH) + " characters long";
    return false;
  }

  // Single-pass character analysis
  int uppercase = 0, lowercase = 0, digits = 0, symbols = 0;
  for (const char c : password) {
    const auto uc = static_cast<unsigned char>(c);
    if (!std::isprint(uc) && c != ' ') {
      error_msg = "Password contains invalid non-printable characters";
      return false;
    }
    if (std::isupper(uc)) {
      ++uppercase;
    } else if (std::islower(uc)) {
      ++lowercase;
    } else if (std::isdigit(uc)) {
      ++digits;
    } else if (std::ispunct(uc) || c == ' ') {
      ++symbols;
    }
  }

  if (uppercase < MIN_UPPERCASE) {
    error_msg = "Password must contain at least " +
                std::to_string(MIN_UPPERCASE) + " uppercase letters";
    return false;
  }
  if (lowercase < MIN_LOWERCASE) {
    error_msg = "Password must contain at least " +
                std::to_string(MIN_LOWERCASE) + " lowercase letters";
    return false;
  }
  if (digits < MIN_DIGITS) {
    error_msg = "Password must contain at least " + std::to_string(MIN_DIGITS) +
                " digits";
    return false;
  }
  if (symbols < MIN_SYMBOLS) {
    error_msg = "Password must contain at least " +
                std::to_string(MIN_SYMBOLS) + " symbols";
    return false;
  }

  return true;
}

//
// FILE UTILITIES
//

std::string extract_extension(std::string_view filename) {
  const auto dot_pos = filename.find_last_of('.');
  if (dot_pos == std::string_view::npos || dot_pos == filename.length() - 1) {
    return "";
  }

  const auto sep_pos = filename.find_last_of("/\\");
  if (sep_pos != std::string_view::npos && sep_pos > dot_pos) {
    return "";
  }

  auto ext = filename.substr(dot_pos);
  // Validate extension doesn't contain invalid characters
  if (ext.find('/') != std::string_view::npos ||
      ext.find('\\') != std::string_view::npos ||
      ext.find("..") != std::string_view::npos) {
    return "";
  }

  return std::string(ext);
}

size_t get_file_size(const std::string &filename) {
  try {
    return static_cast<size_t>(fs::file_size(filename));
  } catch (const fs::filesystem_error &) {
    return 0;
  }
}

std::string auto_generate_output_filename(std::string_view input,
                                          std::string_view mode) {
  const std::string input_str(input);

  if (mode == "encrypt") {
    const auto dot_pos = input.find_last_of('.');
    if (dot_pos != std::string_view::npos) {
      return std::string(input.substr(0, dot_pos)) + ".tre";
    }
    return input_str + ".tre";
  }

  // Decrypt mode: try to read stored extension from file
  std::ifstream infile(input_str, std::ios::binary);
  if (infile) {
    // Skip version byte, salt, nonce to get to extension length
    constexpr size_t HEADER_OFFSET = 1 + SALT_SIZE + NONCE_SIZE;
    infile.seekg(HEADER_OFFSET, std::ios::beg);

    if (infile) {
      unsigned char ext_len = 0;
      infile.read(reinterpret_cast<char *>(&ext_len), 1);

      if (infile.gcount() == 1 && ext_len > 0 && ext_len < 32) {
        std::string stored_ext(ext_len, '\0');
        infile.read(stored_ext.data(), ext_len);

        if (infile.gcount() == ext_len) {
          std::string base = input_str;
          constexpr std::string_view TRE_EXT = ".tre";
          if (base.length() > TRE_EXT.length() &&
              base.substr(base.length() - TRE_EXT.length()) == TRE_EXT) {
            base = base.substr(0, base.length() - TRE_EXT.length());
          }
          return base + stored_ext;
        }
      }
    }
  }

  // Fallback
  if (input.length() > 4 && input.substr(input.length() - 4) == ".tre") {
    return std::string(input.substr(0, input.length() - 4)) + ".txt";
  }
  return input_str + "_decrypted.txt";
}

} // namespace TRE
