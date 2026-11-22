##########################################################################
#  tinyes3-tools
#
#  Build system for the tinyes3 CLI tools, portable between
#  Windows (MSYS2-UCRT64, MinGW) and Linux (GCC).
#
#  Usage with presets (Debug/Release):
#     cmake --preset debug
#     cmake --build --preset debug
#
#     cmake --preset release
#     cmake --build --preset release
#
##########################################################################
cmake_minimum_required(VERSION 3.21)

project(tinyes3-tools LANGUAGES C)

#--------------------------------------------------------------------------
#  Global compiler settings
#--------------------------------------------------------------------------
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

#  Default to a release build if no build type is given
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
   set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
   set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

#--------------------------------------------------------------------------
#  Output directory for the executables
#
#  "bin-release" or "bin-debug" directory in the workspace root, depending
#  on the build type. This way all finished tools are collected in one
#  place.
#
#  NOTE: The prefix "bin-" is used instead of plain "release"/"debug"
#        so that a top-level "release" directory stays free for the
#        distribution of pre-built tools (e.g. as GitHub release assets).
#--------------------------------------------------------------------------
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
   set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin-debug)
else()
   set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin-release)
endif()

#--------------------------------------------------------------------------
#  Compiler warnings
#
#  The warnings are enabled per tool target (see the tool CMakeLists.txt),
#  so the mbedTLS subproject is not affected.
#--------------------------------------------------------------------------

#--------------------------------------------------------------------------
#  Static linking on Windows (MinGW)
#
#  The tools are linked statically, so they can be distributed as a
#  single executable without any additional DLLs (libgcc, winpthread,
#  ...). The UCRT is part of Windows 10/11 and needs no extra DLL.
#--------------------------------------------------------------------------
if(WIN32 AND NOT MSVC)
   add_link_options(-static)

   #  Strip symbols in release builds to reduce the file size
   if(CMAKE_BUILD_TYPE STREQUAL "Release")
      add_link_options(-s)
   endif()
endif()

#--------------------------------------------------------------------------
#  mbedTLS 4.1.2
#
#  mbedTLS is built from source (library/mbedtls) with a custom
#  configuration:
#     - inc/mbedtls_conf.h        (MBEDTLS_CONFIG_FILE)
#     - inc/mbedtls_psa_config.h  (TF_PSA_CRYPTO_CONFIG_FILE)
#--------------------------------------------------------------------------
set(ENABLE_PROGRAMS OFF CACHE BOOL "Build Mbed TLS programs." FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "Build Mbed TLS tests." FORCE)
set(MBEDTLS_CONFIG_FILE
   "${PROJECT_SOURCE_DIR}/inc/mbedtls_conf.h"
   CACHE FILEPATH "Mbed TLS config file (overrides default)." FORCE)
set(TF_PSA_CRYPTO_CONFIG_FILE
   "${PROJECT_SOURCE_DIR}/inc/mbedtls_psa_config.h"
   CACHE FILEPATH "TF-PSA-Crypto config file (overrides default)." FORCE)

#--------------------------------------------------------------------------
#  Shared libraries / sources
#--------------------------------------------------------------------------
add_subdirectory(src)
add_subdirectory(library/mbedtls)
add_subdirectory(library/adler32)

#--------------------------------------------------------------------------
#  Tools
#--------------------------------------------------------------------------
add_subdirectory(es3discover)
add_subdirectory(es3keygen)
add_subdirectory(es3getpub)
add_subdirectory(es3sign)
add_subdirectory(es3verify)
add_subdirectory(es3getpubsign)
add_subdirectory(es3slotlist)
