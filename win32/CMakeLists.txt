cmake_minimum_required(VERSION 3.15)
project(ngrep C)

set(CMAKE_C_STANDARD 99)

# Find Npcap SDK
if(NOT DEFINED NPCAP_SDK_DIR)
    set(NPCAP_SDK_DIR "C:/Program Files/Npcap SDK" CACHE PATH "Npcap SDK directory")
endif()

# Find PCRE2
find_package(PCRE2 QUIET)
if(NOT PCRE2_FOUND)
    # Try to find via vcpkg or manual path
    if(DEFINED ENV{VCPKG_ROOT})
        set(PCRE2_INCLUDE_DIR "$ENV{VCPKG_ROOT}/installed/x64-windows/include")
        set(PCRE2_LIBRARY "$ENV{VCPKG_ROOT}/installed/x64-windows/lib/pcre2-8.lib")
    endif()
endif()

# Source files
set(NGREP_SOURCES
    ../ngrep.c
    ../regex-0.12/regex.c
    support/getopt.c
    support/inet_ntop.c
)

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

# Link libraries
target_link_libraries(ngrep PRIVATE
    ws2_32
    ${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib
    ${NPCAP_SDK_DIR}/Lib/x64/Packet.lib
)

# Optional PCRE2 support
if(PCRE2_FOUND OR PCRE2_INCLUDE_DIR)
    target_compile_definitions(ngrep PRIVATE USE_PCRE2=1 PCRE2_CODE_UNIT_WIDTH=8)
    target_include_directories(ngrep PRIVATE ${PCRE2_INCLUDE_DIR})
    target_link_libraries(ngrep PRIVATE ${PCRE2_LIBRARY})
    message(STATUS "Building with PCRE2 support")
else()
    message(STATUS "Building without PCRE2 support (using regex)")
endif()

# Set output directory
set_target_properties(ngrep PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Installation
install(TARGETS ngrep RUNTIME DESTINATION bin)
