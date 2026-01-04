#ifndef PLATFORM_HPP
#define PLATFORM_HPP

//
// Platform Detection
//
#if defined(_WIN32) || defined(_WIN64)
#define TRE_WINDOWS 1
#define TRE_PLATFORM_NAME "Windows"
#elif defined(__APPLE__) && defined(__MACH__)
#define TRE_MACOS 1
#define TRE_PLATFORM_NAME "macOS"
#elif defined(__linux__)
#define TRE_LINUX 1
#define TRE_PLATFORM_NAME "Linux"
#else
#error "Unsupported platform"
#endif

//
// Platform-Specific Includes
//
#ifdef TRE_WINDOWS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <bcrypt.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <windows.h>
#pragma comment(lib, "bcrypt.lib")
#else
// POSIX (Linux and macOS)
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <cstddef>
#include <cstdint>

namespace TRE {
namespace Platform {

//
// Secure Memory Locking
// Prevents sensitive data (passwords, keys) from being swapped to disk
//

inline bool lock_memory(void *addr, size_t len) {
#ifdef TRE_WINDOWS
  return VirtualLock(addr, len) != 0;
#else
  return mlock(addr, len) == 0;
#endif
}

inline void unlock_memory(void *addr, size_t len) {
#ifdef TRE_WINDOWS
  VirtualUnlock(addr, len);
#else
  munlock(addr, len);
#endif
}

//
// Secure File Operations for secure_delete_file
//

inline int open_file_rw(const char *path) {
#ifdef TRE_WINDOWS
  return _open(path, _O_RDWR | _O_BINARY);
#else
  return open(path, O_RDWR | O_NOFOLLOW);
#endif
}

inline void close_file(int fd) {
#ifdef TRE_WINDOWS
  _close(fd);
#else
  close(fd);
#endif
}

inline int64_t get_file_size_fd(int fd) {
#ifdef TRE_WINDOWS
  struct _stat64 st;
  if (_fstat64(fd, &st) != 0)
    return -1;
  return st.st_size;
#else
  struct stat st;
  if (fstat(fd, &st) != 0)
    return -1;
  return static_cast<int64_t>(st.st_size);
#endif
}

inline int64_t seek_file(int fd, int64_t offset, int whence) {
#ifdef TRE_WINDOWS
  return _lseeki64(fd, offset, whence);
#else
  return lseek(fd, offset, whence);
#endif
}

inline int64_t write_file(int fd, const void *buf, size_t count) {
#ifdef TRE_WINDOWS
  return _write(fd, buf, static_cast<unsigned int>(count));
#else
  return write(fd, buf, count);
#endif
}

inline void sync_file(int fd) {
#ifdef TRE_WINDOWS
  _commit(fd);
#else
  fsync(fd);
#endif
}

//
// System Entropy (True Random)
// Uses hardware-backed random sources on each platform
//

inline bool get_system_random(unsigned char *buffer, size_t size) {
#ifdef TRE_WINDOWS
  // BCryptGenRandom uses TPM, RDRAND, and system entropy pool
  NTSTATUS status = BCryptGenRandom(NULL, buffer, static_cast<ULONG>(size),
                                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  return status == 0; // STATUS_SUCCESS
#else
  // Linux/macOS: /dev/random provides true hardware randomness
  int fd = open("/dev/random", O_RDONLY);
  if (fd < 0)
    return false;

  size_t total_read = 0;
  while (total_read < size) {
    ssize_t n = read(fd, buffer + total_read, size - total_read);
    if (n <= 0) {
      close(fd);
      return false;
    }
    total_read += static_cast<size_t>(n);
  }
  close(fd);
  return true;
#endif
}

} // namespace Platform
} // namespace TRE

#endif // PLATFORM_HPP
