##########################################################################
#  es3getpub
#
#  Get the public key of a key slot from the ES3 signing server
#  via the RPC protocol (UDP, port 54322) and save it as
#  "<slot>.pub" file.
##########################################################################

add_executable(es3getpub
   src/main.c
)

target_link_libraries(es3getpub PRIVATE
   tnp
   mbedtls
)

if(WIN32)
   # GetUserName() lives in advapi32
   target_link_libraries(es3getpub PRIVATE advapi32)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
   target_compile_options(es3getpub PRIVATE -Wall -Wextra)
   # snprintf can theoretically truncate the path buffers, this is intended
   target_compile_options(es3getpub PRIVATE -Wno-format-truncation)
elseif(MSVC)
   target_compile_options(es3getpub PRIVATE /W4)
endif()
