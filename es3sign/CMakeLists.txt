##########################################################################
#  es3sign
#
#  Sign a file with a key slot of the ES3 signing server via the
#  RPC protocol (UDP, port 54322). The output file is written as
#  "<file>.es3" with the ES3 signing header (ES3_SIGN_HEAD).
##########################################################################

add_executable(es3sign
   src/main.c
)

target_link_libraries(es3sign PRIVATE
   tnp
   mbedtls
   adler32
)

if(WIN32)
   # GetUserName() lives in advapi32
   target_link_libraries(es3sign PRIVATE advapi32)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
   target_compile_options(es3sign PRIVATE -Wall -Wextra)
   # snprintf can theoretically truncate the path buffers, this is intended
   target_compile_options(es3sign PRIVATE -Wno-format-truncation)
elseif(MSVC)
   target_compile_options(es3sign PRIVATE /W4)
endif()
