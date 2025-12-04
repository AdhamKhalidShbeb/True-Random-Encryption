cmake_minimum_required(VERSION 3.10)
project(QuantumRandomEncryption VERSION 4.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Security flags
add_compile_options(
    -Wall -Wextra -Wpedantic
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -fPIE
    -mrdrnd # Enable RDRAND instruction support
)

add_link_options(
    -pie
    -Wl,-z,relro,-z,now
)

# Find dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
pkg_check_modules(ZSTD REQUIRED libzstd)

# Add executable
add_executable(qre 
    src/Quantum_Random_Encryption.cpp
    src/entropy/EntropyManager.cpp
)

# Link libraries
target_link_libraries(qre PRIVATE ${SODIUM_LIBRARIES} ${ZSTD_LIBRARIES})
target_include_directories(qre PRIVATE ${SODIUM_INCLUDE_DIRS} ${ZSTD_INCLUDE_DIRS} include)

# Install target
install(TARGETS qre DESTINATION bin)
