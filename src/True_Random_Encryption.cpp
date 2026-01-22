#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sodium.h>
#include <string>
#include <string_view>
#include <vector>

#if defined(_WIN32) || defined(_WIN64)
#define TRE_CLI_WINDOWS 1
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <conio.h>
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#include "compression/CompressionManager.hpp"
#include "core/CryptoCore.hpp"
#include "entropy/EntropyManager.hpp"

using namespace TRE;

inline void secure_delay(unsigned int seconds) {
#ifdef TRE_CLI_WINDOWS
  Sleep(seconds * 1000);
#else
  sleep(seconds);
#endif
}

namespace {
bool g_verbose = false;
CompressionLevel g_compression_level = CompressionLevel::NONE;

inline void vlog(std::string_view msg) {
  if (g_verbose)
    std::cout << "[DEBUG] " << msg << '\n';
}
} // namespace

// Hides password input by disabling terminal echo
class TerminalEchoGuard {
public:
  TerminalEchoGuard() {
#ifdef TRE_CLI_WINDOWS
    hStdin_ = GetStdHandle(STD_INPUT_HANDLE);
    if (hStdin_ != INVALID_HANDLE_VALUE) {
      if (GetConsoleMode(hStdin_, &oldMode_)) {
        DWORD newMode = oldMode_ & ~ENABLE_ECHO_INPUT;
        if (SetConsoleMode(hStdin_, newMode))
          active_ = true;
      }
    }
#else
    if (tcgetattr(STDIN_FILENO, &old_term_) == 0) {
      struct termios new_term = old_term_;
      new_term.c_lflag &= ~static_cast<tcflag_t>(ECHO);
      if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) == 0)
        active_ = true;
    }
#endif
  }

  ~TerminalEchoGuard() {
    if (active_) {
#ifdef TRE_CLI_WINDOWS
      SetConsoleMode(hStdin_, oldMode_);
#else
      tcsetattr(STDIN_FILENO, TCSANOW, &old_term_);
#endif
    }
  }

  TerminalEchoGuard(const TerminalEchoGuard &) = delete;
  TerminalEchoGuard &operator=(const TerminalEchoGuard &) = delete;

private:
#ifdef TRE_CLI_WINDOWS
  HANDLE hStdin_ = INVALID_HANDLE_VALUE;
  DWORD oldMode_ = 0;
#else
  struct termios old_term_{};
#endif
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
            << "  - " << MIN_PASSWORD_LENGTH << "+ characters\n"
            << "  - " << MIN_UPPERCASE << "+ uppercase\n"
            << "  - " << MIN_LOWERCASE << "+ lowercase\n"
            << "  - " << MIN_DIGITS << "+ digits\n"
            << "  - " << MIN_SYMBOLS << "+ symbols\n\n";
}

[[nodiscard]] SecurePassword get_valid_password_for_encryption() {
  SecurePassword password;
  show_password_requirements();

  while (true) {
    std::cout << "Enter password: ";
    std::string temp_password = get_password_hidden();

    if (temp_password.empty()) {
      if (std::cin.eof())
        std::exit(1);
      std::cerr << "Password cannot be empty.\n";
      continue;
    }

    secure_delay(4);

    std::string error_msg;
    if (!validate_password(temp_password, error_msg)) {
      std::cerr << error_msg << "\n\n";
      continue;
    }

    vlog("Password OK");
    password.set(temp_password.c_str(), temp_password.length());
    secure_wipe_string(temp_password);
    return password;
  }
}

[[nodiscard]] SecurePassword get_password_for_decryption() {
  std::cout << "Enter password: ";
  std::string temp_password = get_password_hidden();
  secure_delay(4);

  SecurePassword password;
  password.set(temp_password.c_str(), temp_password.length());
  secure_wipe_string(temp_password);

  if (password.empty()) {
    std::cerr << "Password cannot be empty.\n";
    std::exit(1);
  }

  return password;
}

// Quick sanity checks on startup
[[nodiscard]] bool self_test() {
  vlog("Running self-test...");

  // KDF test
  std::vector<unsigned char> salt(SALT_SIZE, 0xAA);
  auto key = derive_key("test", 4, salt);
  if (key.size() != KEY_SIZE)
    return false;
  vlog("KDF OK");

  // Encryption round-trip
  std::vector<unsigned char> original = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
  std::vector<unsigned char> test_key(KEY_SIZE, 0xCC);
  std::vector<unsigned char> nonce(NONCE_SIZE, 0xEE);

  auto ciphertext = encrypt_aes256gcm(original, test_key, nonce);
  auto decrypted = decrypt_aes256gcm(ciphertext, test_key, nonce);
  if (decrypted != original)
    return false;
  vlog("Encryption OK");

  // Compression
  if (!compression_self_test(g_verbose))
    return false;
  vlog("Compression OK");

  return true;
}

void perform_encryption(const std::string &input_file,
                        const std::string &output_file,
                        const SecurePassword &password) {
  std::ifstream test_file(input_file);
  if (!test_file) {
    std::cerr << "File not found: " << input_file << '\n';
    std::exit(1);
  }
  test_file.close();

  vlog("File size: " + std::to_string(get_file_size(input_file)) + " bytes");

  std::ifstream infile(input_file, std::ios::binary);
  if (!infile)
    std::exit(1);

  vlog("Generating salt...");
  auto salt = EntropyManager::get_instance().get_bytes(SALT_SIZE);
  if (salt.size() != SALT_SIZE)
    std::exit(1);

  vlog("Deriving key...");
  auto key = derive_key(password.c_str(), password.size(), salt);
  auto nonce = EntropyManager::get_instance().get_bytes(NONCE_SIZE);

  std::vector<unsigned char> plaintext((std::istreambuf_iterator<char>(infile)),
                                       std::istreambuf_iterator<char>());
  infile.close();

  if (g_compression_level != CompressionLevel::NONE) {
    vlog("Compressing...");
    plaintext = compress_data(plaintext, g_compression_level);
  }

  vlog("Encrypting...");
  auto ciphertext = encrypt_aes256gcm(plaintext, key, nonce);
  secure_wipe_vector(plaintext);
  secure_wipe_vector(key);

  std::ofstream outfile(output_file, std::ios::binary);
  if (!outfile)
    std::exit(1);

  // Header: [Version][Salt][Nonce][ExtLen][Ext][Comp][Ciphertext]
  outfile.write(reinterpret_cast<const char *>(&FILE_FORMAT_VERSION), 1);
  outfile.write(reinterpret_cast<const char *>(salt.data()), SALT_SIZE);
  outfile.write(reinterpret_cast<const char *>(nonce.data()), NONCE_SIZE);

  const std::string ext = extract_extension(input_file);
  const auto ext_len = static_cast<unsigned char>(ext.length());
  outfile.write(reinterpret_cast<const char *>(&ext_len), 1);
  if (ext_len > 0)
    outfile.write(ext.c_str(), ext_len);

  const auto comp_byte = static_cast<unsigned char>(g_compression_level);
  outfile.write(reinterpret_cast<const char *>(&comp_byte), 1);
  outfile.write(reinterpret_cast<const char *>(ciphertext.data()),
                static_cast<std::streamsize>(ciphertext.size()));
  outfile.close();

  vlog("Done");
}

void perform_decryption(const std::string &input_file,
                        const std::string &output_file,
                        const SecurePassword &password) {
  std::ifstream infile(input_file, std::ios::binary);
  if (!infile)
    std::exit(1);

  unsigned char version = 0;
  infile.read(reinterpret_cast<char *>(&version), 1);
  if (version != FILE_FORMAT_VERSION) {
    std::cerr << "Unsupported file format.\n";
    std::exit(1);
  }

  std::vector<unsigned char> salt(SALT_SIZE);
  infile.read(reinterpret_cast<char *>(salt.data()), SALT_SIZE);

  std::vector<unsigned char> nonce(NONCE_SIZE);
  infile.read(reinterpret_cast<char *>(nonce.data()), NONCE_SIZE);

  unsigned char ext_len = 0;
  infile.read(reinterpret_cast<char *>(&ext_len), 1);
  if (ext_len > 0)
    infile.ignore(ext_len);

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
    std::cerr << "Decryption failed.\n";
    std::exit(1);
  }

  if (comp_level != CompressionLevel::NONE) {
    vlog("Decompressing...");
    plaintext = decompress_data(plaintext);
    if (plaintext.empty())
      std::exit(1);
  }

  std::ofstream outfile(output_file, std::ios::binary);
  if (!outfile)
    std::exit(1);
  outfile.write(reinterpret_cast<const char *>(plaintext.data()),
                static_cast<std::streamsize>(plaintext.size()));
  outfile.close();

  secure_wipe_vector(plaintext);
  secure_wipe_vector(key);
  vlog("Done");
}

void print_usage(const char *prog_name) {
  std::cout << "True Random Encryption (TRE) v1.0\n"
            << "Usage: " << prog_name << " <command> [options] <file>\n\n"
            << "Commands:\n"
            << "  encrypt <file>   Encrypt a file\n"
            << "  decrypt <file>   Decrypt a .tre file\n\n"
            << "Options:\n"
            << "  -h, --help       Show this help message\n"
            << "  -v, --version    Show version information\n"
            << "  --verbose        Enable verbose output\n"
            << "  --compress       Balanced compression (default)\n"
            << "  --compress-fast  Faster compression\n"
            << "  --compress-max   Better compression\n"
            << "  --compress-ultra Maximum compression\n\n"
            << "Examples:\n"
            << "  " << prog_name << " encrypt secret.pdf\n"
            << "  " << prog_name << " decrypt secret.pdf.tre\n";
}

void print_version() {
  std::cout << "True Random Encryption (TRE) v1.0\n"
            << "Copyright (c) 2025 Adham Khalid Shbeb\n"
            << "License: MIT\n";
}

int main(int argc, char *argv[]) {
  if (sodium_init() < 0) {
    std::cerr << "Panic! libsodium failed to initialize\n";
    return 1;
  }

  if (argc < 2) {
    print_usage(argv[0]);
    return 1;
  }

  const std::string_view command = argv[1];

  if (command == "help" || command == "--help" || command == "-h") {
    print_usage(argv[0]);
    return 0;
  }

  if (command == "version" || command == "--version" || command == "-v") {
    // Note: -v is ambiguous (verbose vs version), but as a command it means
    // version
    print_version();
    return 0;
  }

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

  if (command == "encrypt") {
    if (input_file.empty()) {
      std::cerr << "Error: No input file specified.\n";
      return 1;
    }
    if (!self_test()) {
      std::cerr << "Self-test failed! Aborting.\n";
      return 1;
    }
    if (!is_safe_path(input_file)) {
      std::cerr << "Error: Unsafe input path detected.\n";
      return 1;
    }
    auto output_file = auto_generate_output_filename(input_file, "encrypt");
    auto password = get_valid_password_for_encryption();
    perform_encryption(input_file, output_file, password);
  } else if (command == "decrypt") {
    if (input_file.empty()) {
      std::cerr << "Error: No input file specified.\n";
      return 1;
    }
    if (!self_test()) {
      std::cerr << "Self-test failed! Aborting.\n";
      return 1;
    }
    if (!is_safe_path(input_file)) {
      std::cerr << "Error: Unsafe input path detected.\n";
      return 1;
    }
    auto output_file = auto_generate_output_filename(input_file, "decrypt");
    auto password = get_password_for_decryption();
    perform_decryption(input_file, output_file, password);
  } else {
    std::cerr << "Unknown command: " << command << "\n\n";
    print_usage(argv[0]);
    return 1;
  }

  return 0;
}
