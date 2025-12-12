#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <sodium.h>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <vector>

#include "compression/CompressionManager.hpp"
#include "core/CryptoCore.hpp"
#include "entropy/EntropyManager.hpp"

using namespace QRE;

// Global configuration
namespace {
bool g_verbose = false;
CompressionLevel g_compression_level = CompressionLevel::NONE;

inline void vlog(std::string_view msg) {
  if (g_verbose) {
    std::cout << "[DEBUG] " << msg << '\n';
  }
}
} // namespace

//
// INPUT/OUTPUT UTILITIES
//

// RAII guard to ensure terminal echo is restored even on exceptions
class TerminalEchoGuard {
public:
  TerminalEchoGuard() {
    if (tcgetattr(STDIN_FILENO, &old_term_) == 0) {
      struct termios new_term = old_term_;
      new_term.c_lflag &= ~static_cast<tcflag_t>(ECHO);
      if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) == 0) {
        active_ = true;
      }
    }
  }

  ~TerminalEchoGuard() {
    if (active_) {
      tcsetattr(STDIN_FILENO, TCSANOW, &old_term_);
    }
  }

  // Non-copyable, non-movable
  TerminalEchoGuard(const TerminalEchoGuard &) = delete;
  TerminalEchoGuard &operator=(const TerminalEchoGuard &) = delete;
  TerminalEchoGuard(TerminalEchoGuard &&) = delete;
  TerminalEchoGuard &operator=(TerminalEchoGuard &&) = delete;

private:
  struct termios old_term_{};
  bool active_ = false;
};

[[nodiscard]] std::string get_password_hidden() {
  TerminalEchoGuard guard;
  std::string password;
  std::getline(std::cin, password);
  std::cout << '\n';
  return password;
}

void show_password_requirements() {
  std::cout << "\nPassword requirements:\n"
            << "  • Minimum length: " << MIN_PASSWORD_LENGTH << " characters\n"
            << "  • At least " << MIN_UPPERCASE << " uppercase letters\n"
            << "  • At least " << MIN_LOWERCASE << " lowercase letters\n"
            << "  • At least " << MIN_DIGITS << " digits\n"
            << "  • At least " << MIN_SYMBOLS << " symbols\n\n";
}

[[nodiscard]] SecurePassword get_valid_password_for_encryption() {
  SecurePassword password;
  show_password_requirements();

  while (true) {
    std::cout << "Enter password: ";
    std::string temp_password = get_password_hidden();

    if (temp_password.empty()) {
      if (std::cin.eof()) {
        std::cerr << "\n[ERROR] EOF reading password\n";
        std::exit(1);
      }
      std::cerr << "\n[ERROR] Password cannot be empty!\n";
      continue;
    }

    // Rate limiting delay
    sleep(4);

    std::string error_msg;
    if (!validate_password(temp_password, error_msg)) {
      std::cerr << "\n[ERROR] " << error_msg << "\nPlease try again.\n\n";
      continue;
    }

    vlog("Password meets all requirements!");
    password.set(temp_password.c_str(), temp_password.length());
    secure_wipe_string(temp_password);
    return password;
  }
}

[[nodiscard]] SecurePassword get_password_for_decryption() {
  std::cout << "Enter password: ";
  std::string temp_password = get_password_hidden();

  // Rate limiting delay
  sleep(4);

  SecurePassword password;
  password.set(temp_password.c_str(), temp_password.length());
  secure_wipe_string(temp_password);

  if (password.empty()) {
    std::cerr << "Password cannot be empty!\n";
    std::exit(1);
  }

  return password;
}

//
// SELF-TEST ON STARTUP
//

[[nodiscard]] bool self_test() {
  vlog("Running self-test...");

  // Test 1: Argon2id KDF
  {
    std::vector<unsigned char> salt(SALT_SIZE, 0xAA);
    auto key = derive_key("test", 4, salt);
    if (key.size() != KEY_SIZE) {
      std::cerr << "Self-test FAILED: Argon2id\n";
      return false;
    }
    vlog("✓ Argon2id test passed");
  }

  // Test 2: AES-256-GCM encryption round-trip
  {
    std::vector<unsigned char> original = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
    std::vector<unsigned char> key(KEY_SIZE, 0xCC);
    std::vector<unsigned char> nonce(NONCE_SIZE, 0xEE);

    auto ciphertext = encrypt_aes256gcm(original, key, nonce);
    auto decrypted = decrypt_aes256gcm(ciphertext, key, nonce);

    if (decrypted != original) {
      std::cerr << "Self-test FAILED: AES-256-GCM round-trip\n";
      return false;
    }
    vlog("✓ AES-256-GCM encryption test passed");
  }

  // Test 3: Compression round-trip
  if (!compression_self_test(g_verbose)) {
    std::cerr << "Self-test FAILED: Compression\n";
    return false;
  }

  vlog("All self-tests passed!");
  return true;
}

//
// ENCRYPTION/DECRYPTION OPERATIONS
//

void perform_encryption(const std::string &input_file,
                        const std::string &output_file,
                        const SecurePassword &password) {
  // Check if input file exists
  std::ifstream test_file(input_file);
  if (!test_file) {
    std::cerr << "Error: File not found: " << input_file << '\n';
    std::exit(1);
  }
  test_file.close();

  const size_t file_size = get_file_size(input_file);
  vlog("File size: " + std::to_string(file_size) + " bytes");

  std::ifstream infile(input_file, std::ios::binary);
  if (!infile) {
    std::cerr << "Cannot open input file: " << input_file << '\n';
    std::exit(1);
  }

  vlog("Generating hardware random salt...");
  auto salt = EntropyManager::get_instance().get_bytes(SALT_SIZE);
  if (salt.size() != SALT_SIZE) {
    std::cerr << "Error: Failed to generate salt\n";
    std::exit(1);
  }

  vlog("Deriving key...");
  auto key = derive_key(password.c_str(), password.size(), salt);
  auto nonce = EntropyManager::get_instance().get_bytes(NONCE_SIZE);

  std::vector<unsigned char> plaintext((std::istreambuf_iterator<char>(infile)),
                                       std::istreambuf_iterator<char>());
  infile.close();

  if (g_compression_level != CompressionLevel::NONE) {
    vlog("Compressing data...");
    plaintext = compress_data(plaintext, g_compression_level);
  }

  vlog("Encrypting...");
  auto ciphertext = encrypt_aes256gcm(plaintext, key, nonce);
  secure_wipe_vector(plaintext);
  secure_wipe_vector(key);

  std::ofstream outfile(output_file, std::ios::binary);
  if (!outfile) {
    std::cerr << "Error: Cannot open output file: " << output_file << '\n';
    std::exit(1);
  }

  // Write header:
  // [Version:1][Salt:128][Nonce:12][ExtLen:1][Ext:Var][Comp:1][Ciphertext:Var]
  outfile.write(reinterpret_cast<const char *>(&FILE_FORMAT_VERSION), 1);
  outfile.write(reinterpret_cast<const char *>(salt.data()), SALT_SIZE);
  outfile.write(reinterpret_cast<const char *>(nonce.data()), NONCE_SIZE);

  const std::string ext = extract_extension(input_file);
  const auto ext_len = static_cast<unsigned char>(ext.length());
  outfile.write(reinterpret_cast<const char *>(&ext_len), 1);
  if (ext_len > 0) {
    outfile.write(ext.c_str(), ext_len);
  }

  const auto comp_byte = static_cast<unsigned char>(g_compression_level);
  outfile.write(reinterpret_cast<const char *>(&comp_byte), 1);
  outfile.write(reinterpret_cast<const char *>(ciphertext.data()),
                static_cast<std::streamsize>(ciphertext.size()));
  outfile.close();

  vlog("Encryption successful!");
}

void perform_decryption(const std::string &input_file,
                        const std::string &output_file,
                        const SecurePassword &password) {
  std::ifstream infile(input_file, std::ios::binary);
  if (!infile) {
    std::cerr << "Error: Cannot open input file: " << input_file << '\n';
    std::exit(1);
  }

  unsigned char version = 0;
  infile.read(reinterpret_cast<char *>(&version), 1);
  if (version != FILE_FORMAT_VERSION) {
    std::cerr << "Error: Unsupported file version or not a QRE file.\n";
    std::exit(1);
  }

  std::vector<unsigned char> salt(SALT_SIZE);
  infile.read(reinterpret_cast<char *>(salt.data()), SALT_SIZE);

  std::vector<unsigned char> nonce(NONCE_SIZE);
  infile.read(reinterpret_cast<char *>(nonce.data()), NONCE_SIZE);

  unsigned char ext_len = 0;
  infile.read(reinterpret_cast<char *>(&ext_len), 1);
  if (ext_len > 0) {
    infile.ignore(ext_len);
  }

  unsigned char comp_byte = 0;
  infile.read(reinterpret_cast<char *>(&comp_byte), 1);
  const auto comp_level = static_cast<CompressionLevel>(comp_byte);

  std::vector<unsigned char> ciphertext(
      (std::istreambuf_iterator<char>(infile)),
      std::istreambuf_iterator<char>());
  infile.close();

  vlog("Deriving key...");
  auto key = derive_key(password.c_str(), password.size(), salt);

  vlog("Decrypting...");
  auto plaintext = decrypt_aes256gcm(ciphertext, key, nonce);
  if (plaintext.empty()) {
    std::cerr
        << "Error: Decryption failed (wrong password or corrupted file).\n";
    std::exit(1);
  }

  if (comp_level != CompressionLevel::NONE) {
    vlog("Decompressing...");
    plaintext = decompress_data(plaintext);
    if (plaintext.empty()) {
      std::cerr << "Error: Decompression failed.\n";
      std::exit(1);
    }
  }

  std::ofstream outfile(output_file, std::ios::binary);
  if (!outfile) {
    std::cerr << "Error: Cannot open output file: " << output_file << '\n';
    std::exit(1);
  }
  outfile.write(reinterpret_cast<const char *>(plaintext.data()),
                static_cast<std::streamsize>(plaintext.size()));
  outfile.close();

  secure_wipe_vector(plaintext);
  secure_wipe_vector(key);
  vlog("Decryption successful!");
}

//
// MAIN
//

void print_usage(const char *prog_name) {
  std::cout << "Quantum Random Encryption (QRE) v4.0\n"
            << "Usage: " << prog_name << " <command> [options] <file>\n\n"
            << "Commands:\n"
            << "  encrypt <file>   Encrypt a file\n"
            << "  decrypt <file>   Decrypt a file\n\n"
            << "Options:\n"
            << "  -v, --verbose    Enable verbose logging\n"
            << "  --compress       Enable compression (encrypt only)\n"
            << "  --compress-fast  Fast compression\n"
            << "  --compress-max   Max compression\n"
            << "  --compress-ultra Ultra compression\n\n";
}

int main(int argc, char *argv[]) {
  if (sodium_init() < 0) {
    std::cerr << "Panic! libsodium failed to initialize\n";
    return 1;
  }

  if (argc < 3) {
    print_usage(argv[0]);
    return 1;
  }

  const std::string_view command = argv[1];
  std::string input_file;

  // Parse arguments
  for (int i = 2; i < argc; ++i) {
    const std::string_view arg = argv[i];
    if (arg == "-v" || arg == "--verbose") {
      g_verbose = true;
    } else if (arg == "--compress") {
      g_compression_level = CompressionLevel::BALANCED;
    } else if (arg == "--compress-fast") {
      g_compression_level = CompressionLevel::FAST;
    } else if (arg == "--compress-max") {
      g_compression_level = CompressionLevel::MAX;
    } else if (arg == "--compress-ultra") {
      g_compression_level = CompressionLevel::ULTRA;
    } else if (!arg.empty() && arg[0] != '-') {
      input_file = std::string(arg);
    }
  }

  if (input_file.empty()) {
    std::cerr << "Error: No input file specified\n";
    return 1;
  }

  if (!self_test()) {
    std::cerr << "Self-test failed! Aborting.\n";
    return 1;
  }

  if (command == "encrypt") {
    if (!is_safe_path(input_file)) {
      std::cerr << "Error: Unsafe input path detected\n";
      return 1;
    }
    const auto output_file =
        auto_generate_output_filename(input_file, "encrypt");
    auto password = get_valid_password_for_encryption();
    perform_encryption(input_file, output_file, password);
  } else if (command == "decrypt") {
    if (!is_safe_path(input_file)) {
      std::cerr << "Error: Unsafe input path detected\n";
      return 1;
    }
    const auto output_file =
        auto_generate_output_filename(input_file, "decrypt");
    auto password = get_password_for_decryption();
    perform_decryption(input_file, output_file, password);
  } else {
    print_usage(argv[0]);
    return 1;
  }

  return 0;
}
