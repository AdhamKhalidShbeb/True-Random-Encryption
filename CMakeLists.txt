cmake_minimum_required(VERSION 3.10)
project(TrueRandomEncryption VERSION 4.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build/lib)

# Security and warning flags (always applied)
add_compile_options(
    -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
    -fstack-protector-strong
    -fPIE
    -mrdrnd
)

add_link_options(
    -pie
    -Wl,-z,relro,-z,now
)

# Release optimizations
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O3 -DNDEBUG -flto -D_FORTIFY_SOURCE=2)
    add_link_options(-flto)
endif()

# Find dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
pkg_check_modules(ZSTD REQUIRED libzstd)

# Find Qt6
find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

# Core Library
add_library(tre_core
    src/core/CryptoCore.cpp
    src/entropy/EntropyManager.cpp
)
target_include_directories(tre_core PUBLIC include src)
target_link_libraries(tre_core PUBLIC ${SODIUM_LIBRARIES} ${ZSTD_LIBRARIES} Qt6::Core)

# CLI Executable
add_executable(tre 
    src/True_Random_Encryption.cpp
)
target_link_libraries(tre PRIVATE tre_core)

# GUI Executable
set(CMAKE_AUTORCC OFF) # Disable global AUTORCC to avoid path issues with parentheses
qt6_add_resources(TRE_RESOURCES src/gui/resources/resources.qrc)
add_executable(tre-gui
    src/gui/main_gui.cpp
    src/gui/MainWindow.cpp
    ${TRE_RESOURCES}
)
target_link_libraries(tre-gui PRIVATE tre_core Qt6::Widgets)

# Install targets
install(TARGETS tre tre-gui DESTINATION bin)
