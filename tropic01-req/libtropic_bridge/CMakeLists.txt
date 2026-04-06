cmake_minimum_required(VERSION 3.21.0)
include(FetchContent)

project(tropic01_bridge
        DESCRIPTION "Shared library bridge: Python ctypes ↔ libtropic (USB devkit)"
        LANGUAGES C)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
set(PATH_LIBTROPIC "${CMAKE_CURRENT_SOURCE_DIR}/../libtropic/")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
set(LT_USB_DEVKIT_PATH "/dev/ttyACM0"
    CACHE STRING "Default serial port for the TROPIC01 USB devkit.")

set(LT_SH0_KEYS "eng_sample"
    CACHE STRING "Pairing key set: 'eng_sample' or 'prod0'.")
set_property(CACHE LT_SH0_KEYS PROPERTY STRINGS "eng_sample" "prod0")

set(LT_USE_SH0_ENG_SAMPLE 0 CACHE INTERNAL "")
set(LT_USE_SH0_PROD0      0 CACHE INTERNAL "")
if(LT_SH0_KEYS STREQUAL "eng_sample")
    set(LT_USE_SH0_ENG_SAMPLE 1)
else()
    set(LT_USE_SH0_PROD0 1)
endif()

message(STATUS "tropic01_bridge: device=${LT_USB_DEVKIT_PATH}, keys=${LT_SH0_KEYS}")

# Force PIC on every target (required for embedding static libs into a .so)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ---------------------------------------------------------------------------
# Libtropic (static archive)
# ---------------------------------------------------------------------------
add_subdirectory(${PATH_LIBTROPIC} "libtropic")
target_compile_options(tropic PRIVATE -ffunction-sections -fdata-sections)

# ---------------------------------------------------------------------------
# MbedTLS v4 (CAL dependency)
# ---------------------------------------------------------------------------
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    mbedtls_v4
    URL      https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-4.0.0/mbedtls-4.0.0.tar.bz2
    URL_HASH SHA256=2f3a47f7b3a541ddef450e4867eeecb7ce2ef7776093f3a11d6d43ead6bf2827
)
FetchContent_MakeAvailable(mbedtls_v4)
target_link_libraries(tropic PUBLIC mbedtls)

# MbedTLS v4 CAL
add_subdirectory("${PATH_LIBTROPIC}cal/mbedtls_v4" "mbedtls_v4_cal")
target_sources(tropic PRIVATE ${LT_CAL_SRCS})
target_include_directories(tropic PUBLIC ${LT_CAL_INC_DIRS})

# ---------------------------------------------------------------------------
# POSIX USB-dongle HAL
# ---------------------------------------------------------------------------
add_subdirectory("${PATH_LIBTROPIC}hal/posix/usb_dongle" "posix_usb_dongle")
target_sources(tropic PRIVATE ${LT_HAL_SRCS})
target_include_directories(tropic PUBLIC ${LT_HAL_INC_DIRS})

# ---------------------------------------------------------------------------
# Bridge shared library
# ---------------------------------------------------------------------------
add_library(tropic01_bridge SHARED
    tropic01_bridge.c
)

target_compile_definitions(tropic01_bridge PRIVATE
    LT_USE_SH0_ENG_SAMPLE=${LT_USE_SH0_ENG_SAMPLE}
    LT_USE_SH0_PROD0=${LT_USE_SH0_PROD0}
)

target_include_directories(tropic01_bridge PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(tropic01_bridge
    PRIVATE tropic
    PRIVATE pthread
)

# Output the .so into a predictable location inside the build tree
set_target_properties(tropic01_bridge PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    OUTPUT_NAME              "tropic01_bridge"
)
