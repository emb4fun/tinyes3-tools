##########################################################################
#  es3keygen
#
#  Create a private/public es3 key pair (NIST P-256) for the user
#  in the ".es3" folder of the home directory (id_es3 / id_es3.pub).
##########################################################################

add_executable(es3keygen
   src/main.c
)

target_include_directories(es3keygen PRIVATE
   ${PROJECT_SOURCE_DIR}/inc
)

target_link_libraries(es3keygen PRIVATE
   mbedtls
)

if(WIN32)
   # GetUserName() lives in advapi32
   target_link_libraries(es3keygen PRIVATE advapi32)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
   target_compile_options(es3keygen PRIVATE -Wall -Wextra)
   # snprintf can theoretically truncate the path buffers, this is intended
   target_compile_options(es3keygen PRIVATE -Wno-format-truncation)
elseif(MSVC)
   target_compile_options(es3keygen PRIVATE /W4)
endif()
