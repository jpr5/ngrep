cmake_minimum_required(VERSION 3.15)
project(ngrep C)

set(CMAKE_C_STANDARD 99)

# Find Npcap SDK
if(NOT DEFINED NPCAP_SDK_DIR)
    set(NPCAP_SDK_DIR "C:/Program Files/Npcap SDK" CACHE PATH "Npcap SDK directory")
endif()

# Use PCRE2 on Windows to avoid 64-bit issues with ancient regex-0.12
set(USE_PCRE2 ON CACHE BOOL "Use PCRE2 instead of regex-0.12" FORCE)

# Find PCRE2 via vcpkg (note: lowercase 'pcre2' not 'unofficial-pcre2')
find_package(pcre2 CONFIG QUIET)
if(pcre2_FOUND)
    set(PCRE2_LIBRARY PCRE2::8BIT)
    message(STATUS "Found PCRE2 via vcpkg")
else()
    if(CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64")
        message(WARNING "PCRE2 not found - install via: vcpkg install pcre2:arm64-windows")
    else()
        message(WARNING "PCRE2 not found - install via: vcpkg install pcre2:x64-windows")
    endif()
    set(USE_PCRE2 OFF)
endif()

# Source files - conditionally include regex
if(USE_PCRE2)
    set(NGREP_SOURCES
        ../ngrep.c
        support/getopt.c
        support/inet_ntop.c
    )
else()
    set(NGREP_SOURCES
        ../ngrep.c
        ../regex-0.12/regex.c
        support/getopt.c
        support/inet_ntop.c
    )
endif()

# Headers
set(NGREP_HEADERS
    ../ngrep.h
    ../regex-0.12/regex.h
    support/config.h
    support/getopt.h
    support/inet_ntop.h
    support/types.h
)

# Create executable
add_executable(ngrep ${NGREP_SOURCES} ${NGREP_HEADERS})

# Include directories
target_include_directories(ngrep PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/support
    ${CMAKE_CURRENT_SOURCE_DIR}/../regex-0.12
    ${NPCAP_SDK_DIR}/Include
)

# Preprocessor definitions
target_compile_definitions(ngrep PRIVATE
    STDC_HEADERS
    WPCAP
    _CRT_SECURE_NO_WARNINGS
    REGEX_MALLOC
    _WIN32
)

# Link libraries - detect architecture
if(CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64")
    set(NPCAP_LIB_DIR "${NPCAP_SDK_DIR}/Lib/ARM64")
    message(STATUS "Using ARM64 Npcap libraries")
else()
    set(NPCAP_LIB_DIR "${NPCAP_SDK_DIR}/Lib/x64")
    message(STATUS "Using x64 Npcap libraries")
endif()

target_link_libraries(ngrep PRIVATE
    ws2_32
    ${NPCAP_LIB_DIR}/wpcap.lib
    ${NPCAP_LIB_DIR}/Packet.lib
)

# PCRE2 support (enabled by default on Windows)
if(USE_PCRE2)
    target_compile_definitions(ngrep PRIVATE USE_PCRE2=1 PCRE2_CODE_UNIT_WIDTH=8)
    if(DEFINED PCRE2_INCLUDE_DIR)
        target_include_directories(ngrep PRIVATE ${PCRE2_INCLUDE_DIR})
    endif()
    target_link_libraries(ngrep PRIVATE ${PCRE2_LIBRARY})
    message(STATUS "Building with PCRE2 support (avoids 64-bit issues in regex-0.12)")
else()
    target_include_directories(ngrep PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../regex-0.12)
    message(STATUS "Building with regex-0.12 (may have 64-bit warnings)")
endif()

# Set output directory
set_target_properties(ngrep PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Installation
install(TARGETS ngrep RUNTIME DESTINATION bin)
