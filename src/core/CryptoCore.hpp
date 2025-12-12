#ifndef CRYPTO_CORE_HPP
#define CRYPTO_CORE_HPP

#include <filesystem>
#include <sodium.h>
#include <string>
#include <string_view>
#include <vector>

namespace QRE {

namespace fs = std::filesystem;

// Constants - constexpr for compile-time evaluation
inline constexpr int KEY_SIZE = 32;
inline constexpr int SALT_SIZE = 128;
inline constexpr int NONCE_SIZE = 12;
inline constexpr int MIN_PASSWORD_LENGTH = 16;
inline constexpr int MIN_UPPERCASE = 2;
inline constexpr int MIN_LOWERCASE = 2;
inline constexpr int MIN_DIGITS = 2;
inline constexpr int MIN_SYMBOLS = 2;
inline constexpr unsigned char FILE_FORMAT_VERSION = 0x03;

// Secure Memory Utilities
void secure_wipe_string(std::string &s) noexcept;
void secure_wipe_vector(std::vector<unsigned char> &v) noexcept;
[[nodiscard]] bool secure_delete_file(const std::string &filename);
[[nodiscard]] bool is_safe_path(const std::string &path);

// Secure Password Class - RAII for password memory
class SecurePassword {
private:
  char *data_ = nullptr;
  size_t capacity_ = 0;
  size_t length_ = 0;

public:
  explicit SecurePassword(size_t max_len = 256);
  ~SecurePassword();

  // Non-copyable
  SecurePassword(const SecurePassword &) = delete;
  SecurePassword &operator=(const SecurePassword &) = delete;

  // Movable
  SecurePassword(SecurePassword &&other) noexcept;
  SecurePassword &operator=(SecurePassword &&other) noexcept;

  void set(const char *input, size_t len);
  [[nodiscard]] const char *c_str() const noexcept { return data_; }
  [[nodiscard]] size_t size() const noexcept { return length_; }
  [[nodiscard]] bool empty() const noexcept { return length_ == 0; }
};

// Cryptographic Functions
[[nodiscard]] std::vector<unsigned char>
derive_key(const char *password, size_t password_len,
           const std::vector<unsigned char> &salt);

[[nodiscard]] std::vector<unsigned char>
encrypt_aes256gcm(const std::vector<unsigned char> &plaintext,
                  const std::vector<unsigned char> &key,
                  const std::vector<unsigned char> &nonce);

[[nodiscard]] std::vector<unsigned char>
decrypt_aes256gcm(const std::vector<unsigned char> &ciphertext,
                  const std::vector<unsigned char> &key,
                  const std::vector<unsigned char> &nonce);

// Validation
[[nodiscard]] bool validate_password(std::string_view password,
                                     std::string &error_msg);

// File Utilities
[[nodiscard]] std::string extract_extension(std::string_view filename);
[[nodiscard]] size_t get_file_size(const std::string &filename);
[[nodiscard]] std::string auto_generate_output_filename(std::string_view input,
                                                        std::string_view mode);

} // namespace QRE

#endif // CRYPTO_CORE_HPP
