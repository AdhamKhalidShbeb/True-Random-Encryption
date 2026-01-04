cmake_minimum_required(VERSION 3.10)
project(TrueRandomEncryption VERSION 4.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Platform detection
if(WIN32)
    set(TRE_PLATFORM "windows")
    message(STATUS "Building for Windows")
elseif(APPLE)
    set(TRE_PLATFORM "macos")
    message(STATUS "Building for macOS")
else()
    set(TRE_PLATFORM "linux")
    message(STATUS "Building for Linux")
endif()

# Output directories - organized by platform
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin/${TRE_PLATFORM})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build/lib)

# Platform-specific compiler options
if(MSVC)
    # Windows MSVC compiler flags
    add_compile_options(
        /W4           # High warning level
        /WX-          # Don't treat warnings as errors
        /GS           # Buffer security check
        /sdl          # Additional security checks
    )
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(/O2 /GL /DNDEBUG)
        add_link_options(/LTCG)
    endif()
else()
    # GCC/Clang (Linux and macOS)
    add_compile_options(
        -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
        -fstack-protector-strong
        -fPIE
    )
    # RDRAND is Intel-specific, check for x86 architecture
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i686")
        add_compile_options(-mrdrnd)
    endif()
    add_link_options(-pie)
    # Linux-specific linker options
    if(NOT APPLE)
        add_link_options(-Wl,-z,relro,-z,now)
    endif()
    # Release optimizations
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(-O3 -DNDEBUG -flto)
        if(NOT APPLE)
            add_compile_options(-D_FORTIFY_SOURCE=2)
        endif()
        add_link_options(-flto)
    endif()
endif()

# Find dependencies
if(NOT WIN32)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED libsodium)
    pkg_check_modules(ZSTD REQUIRED libzstd)
else()
    # Windows: Look for vcpkg or manual installation
    find_package(unofficial-sodium CONFIG)
    find_package(zstd CONFIG)
    if(unofficial-sodium_FOUND)
        set(SODIUM_LIBRARIES unofficial-sodium::sodium)
    endif()
    if(zstd_FOUND)
        set(ZSTD_LIBRARIES zstd::libzstd_shared)
    endif()
endif()

# Find Qt6
find_package(Qt6 COMPONENTS Core Gui Widgets Svg REQUIRED)

# Core Library
add_library(tre_core
    src/core/CryptoCore.cpp
    src/entropy/EntropyManager.cpp
)
target_include_directories(tre_core PUBLIC include src)
target_link_libraries(tre_core PUBLIC ${SODIUM_LIBRARIES} ${ZSTD_LIBRARIES} Qt6::Core)

# Windows-specific: Link bcrypt for entropy
if(WIN32)
    target_link_libraries(tre_core PUBLIC bcrypt)
endif()

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
target_link_libraries(tre-gui PRIVATE tre_core Qt6::Widgets Qt6::Svg)

# Windows-specific: Hide console window for GUI
if(WIN32)
    set_target_properties(tre-gui PROPERTIES WIN32_EXECUTABLE TRUE)
endif()

# macOS-specific: Create app bundle
if(APPLE)
    set_target_properties(tre-gui PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_GUI_IDENTIFIER "com.tre.gui"
        MACOSX_BUNDLE_BUNDLE_NAME "True Random Encryption"
    )
endif()

# Install targets
install(TARGETS tre tre-gui DESTINATION bin)
