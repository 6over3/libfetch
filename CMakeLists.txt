cmake_minimum_required(VERSION 4.0.0)
cmake_policy(SET CMP0135 NEW)

# =============================================================================
# Project Configuration
# =============================================================================

# Include Git version function before project declaration
include(cmake/GetGitVersion.cmake)
get_git_version(GIT_VERSION WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

# Extract version components from Git tag
if(GIT_VERSION AND GIT_VERSION MATCHES "v?([0-9]+)\\.([0-9]+)\\.([0-9]+)")
    set(PROJECT_VERSION_MAJOR ${CMAKE_MATCH_1})
    set(PROJECT_VERSION_MINOR ${CMAKE_MATCH_2})
    set(PROJECT_VERSION_PATCH ${CMAKE_MATCH_3})
    set(PROJECT_VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")
else()
    # Fallback version
    set(GIT_VERSION "v1.0.0")
    set(PROJECT_VERSION "1.0.0")
    set(PROJECT_VERSION_MAJOR 1)
    set(PROJECT_VERSION_MINOR 0)
    set(PROJECT_VERSION_PATCH 0)
    message(WARNING "Could not determine version from Git tags, using fallback: ${PROJECT_VERSION}")
endif()

project(libfetch
    DESCRIPTION "libfetch - A lightweight asynchronous HTTP/1.1 client library."
    LANGUAGES C CXX
    VERSION ${PROJECT_VERSION}
    HOMEPAGE_URL "https://github.com/6over3/libfetch"
)

# =============================================================================
# Build Options and Standards
# =============================================================================

# Language standards
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Ada dependency configuration
set(ADA_TESTING OFF CACHE BOOL "Disable Ada testing" FORCE)
set(ADA_TOOLS OFF CACHE BOOL "Disable Ada tools" FORCE)

# Build type
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# Build options
option(LIBFETCH_ENABLE_TLS "Enable TLS/SSL support" OFF)
option(LIBFETCH_BUILD_TESTS "Build unit tests" ON)
option(LIBFETCH_BUILD_EXAMPLES "Build example programs" OFF)
option(LIBFETCH_BUILD_DOCS "Build documentation" OFF)
option(LIBFETCH_INSTALL "Generate install target" ON)

# =============================================================================
# Compiler Configuration
# =============================================================================

if(MSVC)
    # Use target-specific options instead of global flags to avoid being overridden
    add_compile_definitions(
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _WIN32_WINNT=0x0A00
        UNICODE
        _UNICODE
    )
    
    # Disable specific warnings
    add_compile_options(/wd4996) # Disable deprecated function warnings
    
    # Link-time optimization for release
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(/GL)
        add_link_options(/LTCG)
    endif()
else()
    # GCC/Clang flags
    set(CMAKE_C_FLAGS_DEBUG "-g -fsanitize=address -fno-omit-frame-pointer -O0 -DDEBUG")
    set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG -march=native -flto")
    set(CMAKE_CXX_FLAGS_DEBUG "-g -fsanitize=address -fno-omit-frame-pointer -O0 -DDEBUG")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -march=native -flto")

    # Release optimizations
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(-fno-stack-protector -fno-common -pipe)
        add_link_options(-flto -Wl,-O3)
        
        if(CMAKE_C_COMPILER_ID STREQUAL "AppleClang")
            add_link_options(-Wl,-dead_strip)
        elseif(NOT CMAKE_C_COMPILER_ID STREQUAL "AppleClang")
            add_link_options(-Wl,--gc-sections -Wl,--strip-all)
        endif()
    endif()
endif()

# =============================================================================
# Dependencies
# =============================================================================

include(FetchContent)

# Set fetch content options
set(FETCHCONTENT_QUIET OFF)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)

# Ada URL parser
FetchContent_Declare(
    ada
    GIT_REPOSITORY https://github.com/ada-url/ada.git
    GIT_TAG v2.7.4  # Use specific version for reproducibility
    GIT_SHALLOW TRUE
)

# Documentation styling (only if building docs)
if(LIBFETCH_BUILD_DOCS)
    find_package(Doxygen)
    if(DOXYGEN_FOUND)
        FetchContent_Declare(
            doxygen-awesome-css
            URL https://github.com/jothepro/doxygen-awesome-css/archive/refs/heads/main.zip
        )
        FetchContent_MakeAvailable(doxygen-awesome-css)
        FetchContent_GetProperties(doxygen-awesome-css SOURCE_DIR AWESOME_CSS_DIR)
    endif()
endif()

FetchContent_MakeAvailable(ada)

# TLS/SSL Support
if(LIBFETCH_ENABLE_TLS)
    # Manual OpenSSL configuration support
    if(DEFINED OPENSSL_CRYPTO_LIBRARY AND DEFINED OPENSSL_SSL_LIBRARY AND DEFINED OPENSSL_INCLUDE_DIR)
        message(STATUS "Using manually specified OpenSSL paths")
        
        # Validate paths
        if(NOT EXISTS "${OPENSSL_INCLUDE_DIR}/openssl/ssl.h")
            message(FATAL_ERROR "OpenSSL header not found at: ${OPENSSL_INCLUDE_DIR}/openssl/ssl.h")
        endif()
        if(NOT EXISTS "${OPENSSL_CRYPTO_LIBRARY}")
            message(FATAL_ERROR "OpenSSL crypto library not found at: ${OPENSSL_CRYPTO_LIBRARY}")
        endif()
        if(NOT EXISTS "${OPENSSL_SSL_LIBRARY}")
            message(FATAL_ERROR "OpenSSL SSL library not found at: ${OPENSSL_SSL_LIBRARY}")
        endif()
        
        # Create imported targets
        add_library(OpenSSL::Crypto UNKNOWN IMPORTED)
        set_target_properties(OpenSSL::Crypto PROPERTIES
            IMPORTED_LOCATION "${OPENSSL_CRYPTO_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
        )
        
        add_library(OpenSSL::SSL UNKNOWN IMPORTED)
        set_target_properties(OpenSSL::SSL PROPERTIES
            IMPORTED_LOCATION "${OPENSSL_SSL_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
            INTERFACE_LINK_LIBRARIES "OpenSSL::Crypto"
        )
        
        set(OPENSSL_FOUND TRUE)
        set(OPENSSL_VERSION "Manual")
    else()
        # Standard OpenSSL search
        if(WIN32)
            set(OPENSSL_USE_STATIC_LIBS TRUE)
        endif()
        
        find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)
    endif()
    
    if(NOT OPENSSL_FOUND)
        message(FATAL_ERROR "OpenSSL not found. TLS support requires OpenSSL.")
    endif()
    
    message(STATUS "TLS support enabled with OpenSSL ${OPENSSL_VERSION}")
endif()

# =============================================================================
# Library Target
# =============================================================================

# Collect source files
file(GLOB_RECURSE LIB_SOURCES 
    CONFIGURE_DEPENDS
    "src/*.c"
)
list(REMOVE_ITEM LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/main.c")

file(GLOB_RECURSE LIB_HEADERS 
    CONFIGURE_DEPENDS
    "src/*.h"
)

if(NOT LIB_SOURCES)
    message(FATAL_ERROR "No source files found in src/ directory")
endif()

# Generate version header
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/version.h"
    @ONLY
)

# Create library
add_library(libfetch ${LIB_SOURCES})
add_library(libfetch::libfetch ALIAS libfetch)

# MSVC-specific C11 atomics configuration (must be done per-target)
if(MSVC)
    target_compile_options(libfetch PRIVATE 
        /std:c11 
        /experimental:c11atomics
        $<$<CONFIG:Debug>:/Od /Zi /RTC1 /MDd /DDEBUG>
        $<$<CONFIG:Release>:/O2 /Ob2 /DNDEBUG /MD>
    )
endif()

# Set target properties
set_target_properties(libfetch PROPERTIES
    OUTPUT_NAME fetch
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    EXPORT_NAME libfetch
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

# Include directories
target_include_directories(libfetch
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/internal
)

# Link dependencies
target_link_libraries(libfetch
    PUBLIC
        ada::ada
)

# TLS configuration
if(LIBFETCH_ENABLE_TLS)
    target_compile_definitions(libfetch 
        PUBLIC 
            LIBFETCH_TLS_ENABLED
            OPENSSL_NO_DEPRECATED_1_1_0
    )
    target_link_libraries(libfetch PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    
    # Platform-specific TLS dependencies
    if(MSVC AND TARGET OpenSSL::applink)
        target_link_libraries(libfetch PRIVATE OpenSSL::applink)
    endif()
    
    if(WIN32)
        target_link_libraries(libfetch PUBLIC crypt32 user32)
    elseif(UNIX AND NOT APPLE)
        target_link_libraries(libfetch PUBLIC dl)
    elseif(APPLE)
        find_library(COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
        find_library(SECURITY_FRAMEWORK Security REQUIRED)
        target_link_libraries(libfetch PUBLIC ${COREFOUNDATION_FRAMEWORK} ${SECURITY_FRAMEWORK})
    endif()
endif()

# Platform-specific libraries
if(WIN32)
    target_link_libraries(libfetch PUBLIC ws2_32 winmm)
elseif(UNIX)
    target_link_libraries(libfetch PUBLIC pthread)
    if(NOT APPLE)
        target_link_libraries(libfetch PUBLIC anl)
    endif()
endif()

# =============================================================================
# Executable Target
# =============================================================================

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/main.c")
    add_executable(fetch-cli src/main.c)
    target_link_libraries(fetch-cli PRIVATE libfetch::libfetch)
    
    # MSVC C11 atomics for CLI as well
    if(MSVC)
        target_compile_options(fetch-cli PRIVATE 
            /std:c11 
            /experimental:c11atomics
            $<$<CONFIG:Debug>:/Od /Zi /RTC1 /MDd /DDEBUG>
            $<$<CONFIG:Release>:/O2 /Ob2 /DNDEBUG /MD>
        )
    endif()
    
    set_target_properties(fetch-cli PROPERTIES
        OUTPUT_NAME fetch
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )
endif()

# =============================================================================
# Testing
# =============================================================================

if(LIBFETCH_BUILD_TESTS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests")
    enable_testing()
    
    # Find test files
    file(GLOB_RECURSE TEST_SOURCES 
        CONFIGURE_DEPENDS
        "tests/test_*.c"
    )
    
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/unity.c" AND TEST_SOURCES)
        # Unity test framework
        add_library(unity STATIC tests/unity.c)
        target_include_directories(unity PUBLIC tests)
        
        # Create test executables
        foreach(TEST_SOURCE ${TEST_SOURCES})
            get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)
            
            add_executable(${TEST_NAME} ${TEST_SOURCE})
            target_link_libraries(${TEST_NAME} 
                PRIVATE 
                    unity 
                    libfetch::libfetch
            )
            target_include_directories(${TEST_NAME} 
                PRIVATE 
                    tests 
                    src
            )
            
            # MSVC C11 atomics for tests
            if(MSVC)
                target_compile_options(${TEST_NAME} PRIVATE 
                    /std:c11 
                    /experimental:c11atomics
                )
            endif()
            
            add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
            set_tests_properties(${TEST_NAME} PROPERTIES
                TIMEOUT 300
                LABELS "unit_test"
            )
        endforeach()
        
        # Test convenience targets
        add_custom_target(run_tests
            COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Running all tests"
        )
        
        list(LENGTH TEST_SOURCES TEST_COUNT)
        message(STATUS "Tests enabled: ${TEST_COUNT} test(s) found")
    else()
        message(WARNING "Test framework or test files not found, tests disabled")
    endif()
endif()

# =============================================================================
# Documentation
# =============================================================================

if(LIBFETCH_BUILD_DOCS AND DOXYGEN_FOUND)
    set(DOXYFILE_IN ${CMAKE_CURRENT_SOURCE_DIR}/doc/Doxyfile.in)
    set(DOXYFILE_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
    
    if(EXISTS ${DOXYFILE_IN})
        configure_file(${DOXYFILE_IN} ${DOXYFILE_OUT} @ONLY)
        
        add_custom_target(docs
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYFILE_OUT}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating documentation with Doxygen"
            VERBATIM
        )
    endif()
endif()

# =============================================================================
# Installation
# =============================================================================

if(LIBFETCH_INSTALL)
    include(GNUInstallDirs)
    include(CMakePackageConfigHelpers)
    
    # Install library
    install(TARGETS libfetch
        EXPORT libfetchTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )
    
    # Install headers
    install(FILES ${LIB_HEADERS}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libfetch
    )
    
    # Install generated version header
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/version.h"
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libfetch
    )
    
    # Install executable
    if(TARGET fetch-cli)
        install(TARGETS fetch-cli
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )
    endif()
    
    # Generate and install CMake config files
    set(CONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/libfetch)
    
    configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/libfetch-config.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/libfetch-config.cmake"
        INSTALL_DESTINATION ${CONFIG_INSTALL_DIR}
        PATH_VARS CMAKE_INSTALL_INCLUDEDIR CMAKE_INSTALL_LIBDIR
    )
    
    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/libfetch-config-version.cmake"
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY AnyNewerVersion
    )
    
    install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/libfetch-config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/libfetch-config-version.cmake"
        DESTINATION ${CONFIG_INSTALL_DIR}
    )
    
    install(EXPORT libfetchTargets
        FILE libfetchTargets.cmake
        NAMESPACE libfetch::
        DESTINATION ${CONFIG_INSTALL_DIR}
    )
    
    # Create uninstall target
    if(NOT TARGET uninstall AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in")
        configure_file(
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
            "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
            IMMEDIATE @ONLY
        )
        
        add_custom_target(uninstall
            COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
        )
    endif()
endif()

# =============================================================================
# Package Configuration (CPack)
# =============================================================================

set(CPACK_PACKAGE_NAME "libfetch")
set(CPACK_PACKAGE_VENDOR "Your Organization")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "LibFetch - A modern HTTP client library")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})

# Only set license and readme if files exist
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
endif()
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
    set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
endif()

if(WIN32)
    set(CPACK_GENERATOR "ZIP;NSIS")
elseif(APPLE)
    set(CPACK_GENERATOR "TGZ;productbuild")
else()
    set(CPACK_GENERATOR "TGZ;DEB;RPM")
endif()

include(CPack)

# =============================================================================
# Development Targets
# =============================================================================

# Code formatting
find_program(CLANG_FORMAT_EXECUTABLE clang-format)
if(CLANG_FORMAT_EXECUTABLE)
    file(GLOB_RECURSE ALL_SOURCE_FILES
        CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.[ch]"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.[ch]"
    )
    
    add_custom_target(format
        COMMAND ${CLANG_FORMAT_EXECUTABLE} -i ${ALL_SOURCE_FILES}
        COMMENT "Formatting source code"
    )
    
    add_custom_target(format-check
        COMMAND ${CLANG_FORMAT_EXECUTABLE} --dry-run --Werror ${ALL_SOURCE_FILES}
        COMMENT "Checking source code formatting"
    )
endif()

# Static analysis
find_program(CPPCHECK_EXECUTABLE cppcheck)
if(CPPCHECK_EXECUTABLE)
    add_custom_target(cppcheck
        COMMAND ${CPPCHECK_EXECUTABLE}
            --enable=all
            --std=c11
            --verbose
            --quiet
            --error-exitcode=1
            ${CMAKE_CURRENT_SOURCE_DIR}/src
        COMMENT "Running static analysis"
    )
endif()

# =============================================================================
# Status Messages
# =============================================================================

message(STATUS "")
message(STATUS "=== LibFetch Configuration Summary ===")
message(STATUS "Version:          ${PROJECT_VERSION} (${GIT_VERSION})")
message(STATUS "Build type:       ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler:       ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
if(MSVC)
    message(STATUS "MSVC Version:     ${MSVC_VERSION}")
    message(STATUS "MSVC Toolset:     ${CMAKE_VS_PLATFORM_TOOLSET}")
    message(STATUS "C11 Atomics:      Enabled (per-target /std:c11 /experimental:c11atomics)")
endif()
message(STATUS "Install prefix:   ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Header directory: ${CMAKE_CURRENT_BINARY_DIR} (version.h)")
message(STATUS "")
message(STATUS "Features:")
message(STATUS "  TLS support:    ${LIBFETCH_ENABLE_TLS}")
if(LIBFETCH_ENABLE_TLS)
    message(STATUS "  OpenSSL version: ${OPENSSL_VERSION}")
endif()
message(STATUS "  Build tests:    ${LIBFETCH_BUILD_TESTS}")
message(STATUS "  Build docs:     ${LIBFETCH_BUILD_DOCS}")
message(STATUS "  Build examples: ${LIBFETCH_BUILD_EXAMPLES}")
message(STATUS "  Install target: ${LIBFETCH_INSTALL}")
message(STATUS "")
message(STATUS "Targets available:")
message(STATUS "  libfetch        - Static library")
if(TARGET fetch-cli)
    message(STATUS "  fetch-cli       - Command line tool")
endif()
if(LIBFETCH_BUILD_TESTS)
    message(STATUS "  run_tests       - Run all tests")
endif()
if(LIBFETCH_BUILD_DOCS AND DOXYGEN_FOUND)
    message(STATUS "  docs           - Generate documentation")
endif()
if(CLANG_FORMAT_EXECUTABLE)
    message(STATUS "  format         - Format source code")
endif()
message(STATUS "======================================")
message(STATUS "")