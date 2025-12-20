#pragma once

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

namespace TRE {

class TarManager {
private:
  // Validate that a path doesn't contain shell metacharacters
  [[nodiscard]] static bool is_safe_shell_path(std::string_view path) noexcept {
    // Reject paths with characters that could allow shell injection
    for (char c : path) {
      if (c == '$' || c == '`' || c == ';' || c == '|' || c == '&' ||
          c == '>' || c == '<' || c == '\n' || c == '\r' || c == '\0') {
        return false;
      }
    }
    return true;
  }

public:
  // Check if tar command is available
  [[nodiscard]] static bool is_tar_available() noexcept {
    return std::system("tar --version > /dev/null 2>&1") == 0;
  }

  // Create a tar archive from a directory
  [[nodiscard]] static bool create_archive(std::string_view source_dir,
                                           std::string_view output_tar) {
    if (!is_tar_available()) {
      std::cerr << "Error: 'tar' command not found. Please install tar.\n";
      return false;
    }

    // Security: Validate paths against shell injection
    if (!is_safe_shell_path(source_dir) || !is_safe_shell_path(output_tar)) {
      std::cerr << "Error: Path contains unsafe characters.\n";
      return false;
    }

    std::string clean_source(source_dir);
    if (!clean_source.empty() && clean_source.back() == '/') {
      clean_source.pop_back();
    }

    const std::filesystem::path source_path(clean_source);
    std::string parent_dir = source_path.parent_path().string();
    const std::string dir_name = source_path.filename().string();

    if (parent_dir.empty()) {
      parent_dir = ".";
    }

    std::ostringstream cmd;
    cmd << "tar -cf \"" << output_tar << "\" -C \"" << parent_dir << "\" \""
        << dir_name << "\" > /dev/null 2>&1";

    return std::system(cmd.str().c_str()) == 0;
  }

  // Extract a tar archive
  [[nodiscard]] static bool extract_archive(std::string_view input_tar,
                                            std::string_view dest_dir = ".") {
    if (!is_tar_available()) {
      std::cerr << "Error: 'tar' command not found.\n";
      return false;
    }

    // Security: Validate paths against shell injection
    if (!is_safe_shell_path(input_tar) || !is_safe_shell_path(dest_dir)) {
      std::cerr << "Error: Path contains unsafe characters.\n";
      return false;
    }

    if (!dest_dir.empty() && dest_dir != ".") {
      std::filesystem::create_directories(std::string(dest_dir));
    }

    std::ostringstream cmd;
    cmd << "tar -xf \"" << input_tar << "\"";

    if (!dest_dir.empty() && dest_dir != ".") {
      cmd << " -C \"" << dest_dir << "\"";
    }

    cmd << " > /dev/null 2>&1";
    return std::system(cmd.str().c_str()) == 0;
  }
};

} // namespace TRE
