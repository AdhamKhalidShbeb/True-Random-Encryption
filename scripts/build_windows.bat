@echo off
REM Windows Build Script for True Random Encryption
REM Requires: CMake, Visual Studio 2019/2022, Qt6, vcpkg (for libsodium and zstd)

echo ============================================
echo  True Random Encryption - Windows Build
echo ============================================

REM Check for CMake
where cmake >nul 2>nul
if errorlevel 1 (
    echo ERROR: CMake not found. Please install CMake and add to PATH.
    exit /b 1
)

REM Create build directory
if not exist build mkdir build
cd build

REM Configure with CMake
echo.
echo Configuring with CMake...
cmake -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release ..
if errorlevel 1 (
    echo ERROR: CMake configuration failed.
    cd ..
    exit /b 1
)

REM Build
echo.
echo Building...
cmake --build . --config Release
if errorlevel 1 (
    echo ERROR: Build failed.
    cd ..
    exit /b 1
)

cd ..

echo.
echo ============================================
echo  Build complete!
echo  Output: bin\windows\
echo ============================================
echo.
dir bin\windows\
