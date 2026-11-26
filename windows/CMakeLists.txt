cmake_minimum_required(VERSION 3.24)
project(quickunlocker LANGUAGES CXX)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Quickunlocker requires a 64-bit Windows toolchain. Use MSVC with -A x64.")
endif()

include(FetchContent)
FetchContent_Declare(nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
    URL_HASH SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa
)
FetchContent_MakeAvailable(nlohmann_json)

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    add_compile_options(/W4 /permissive- /EHsc /utf-8)
endif()

add_library(quickunlock_common STATIC common/webauthn.cpp common/http.cpp common/config.cpp)
target_compile_features(quickunlock_common PUBLIC cxx_std_20)
target_compile_definitions(quickunlock_common PUBLIC UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00 NTDDI_VERSION=0x0A000000)
target_include_directories(quickunlock_common PUBLIC common)
target_link_libraries(quickunlock_common PUBLIC nlohmann_json::nlohmann_json bcrypt crypt32 winhttp advapi32)

option(QUICKUNLOCKER_COVERAGE "Enable Clang source-based coverage for CTest targets" OFF)
if(QUICKUNLOCKER_COVERAGE)
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR "QUICKUNLOCKER_COVERAGE requires Clang.")
    endif()
    if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
        if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "22")
            message(FATAL_ERROR "The Visual Studio coverage build requires clang-cl 22 or newer. Pass -LlvmRoot to collect-coverage.ps1 to select that LLVM installation.")
        endif()
        target_compile_options(quickunlock_common PUBLIC /clang:-fprofile-instr-generate /clang:-fcoverage-mapping)
        # clang-cl injects a reference to its profiling library into instrumented objects.
        execute_process(
            COMMAND "${CMAKE_CXX_COMPILER}" -print-resource-dir
            OUTPUT_VARIABLE clang_resource_dir
            OUTPUT_STRIP_TRAILING_WHITESPACE
            COMMAND_ERROR_IS_FATAL ANY
        )
        target_link_directories(quickunlock_common PUBLIC "${clang_resource_dir}/lib/windows")
    else()
        target_compile_options(quickunlock_common PUBLIC -fprofile-instr-generate -fcoverage-mapping)
        target_link_options(quickunlock_common PUBLIC -fprofile-instr-generate)
    endif()
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(webauthn_test tests/webauthn_test.cpp)
    target_link_libraries(webauthn_test PRIVATE quickunlock_common)
    add_test(NAME webauthn COMMAND webauthn_test "${CMAKE_CURRENT_SOURCE_DIR}/tests/assertions.json")
endif()

FetchContent_Declare(qrcodegen
    URL https://codeload.github.com/nayuki/QR-Code-generator/tar.gz/refs/tags/v1.8.0
    URL_HASH SHA256=2ec0a4d33d6f521c942eeaf473d42d5fe139abcfa57d2beffe10c5cf7d34ae60
)
FetchContent_MakeAvailable(qrcodegen)
add_library(quickunlock_qr STATIC "${qrcodegen_SOURCE_DIR}/cpp/qrcodegen.cpp")
target_include_directories(quickunlock_qr SYSTEM PUBLIC "${qrcodegen_SOURCE_DIR}/cpp")

add_library(quickunlock_setup_enrollment STATIC setup/enrollment.cpp)
target_include_directories(quickunlock_setup_enrollment PUBLIC setup)
target_link_libraries(quickunlock_setup_enrollment PUBLIC quickunlock_common)

add_executable(quickunlocker-setup setup/setup.cpp)
target_link_libraries(quickunlocker-setup PRIVATE quickunlock_setup_enrollment quickunlock_qr iphlpapi shell32 ole32 uuid)
if(MSVC)
    target_link_options(quickunlocker-setup PRIVATE "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'")
elseif(MINGW)
    target_link_options(quickunlocker-setup PRIVATE -municode)
endif()

add_library(quickunlocker SHARED credprov/credprov.cpp credprov/serialization.cpp credprov/credprov.def)
set_target_properties(quickunlocker PROPERTIES PREFIX "")
target_link_libraries(quickunlocker PRIVATE quickunlock_common ole32 uuid secur32 user32 gdi32)

if(BUILD_TESTING)
    add_executable(provider_test tests/provider_test.cpp)
    target_link_libraries(provider_test PRIVATE quickunlock_common ole32 uuid)
    if(MINGW)
        target_link_options(provider_test PRIVATE -municode)
    endif()
    add_dependencies(provider_test quickunlocker)
    add_test(NAME credential_provider COMMAND provider_test "$<TARGET_FILE:quickunlocker>")
endif()

if(BUILD_TESTING)
    add_executable(setup_test tests/setup_test.cpp)
    target_link_libraries(setup_test PRIVATE quickunlock_setup_enrollment)
    add_test(NAME setup_enrollment COMMAND setup_test "${CMAKE_CURRENT_SOURCE_DIR}/tests/assertions.json")

    set_tests_properties(webauthn credential_provider setup_enrollment PROPERTIES TIMEOUT 20)
endif()
