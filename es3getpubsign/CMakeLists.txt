##########################################################################
#  es3getpubsign
#
#  Get the public key of a key slot from the ES3 signing server and
#  have it signed by the server with the special "root-of-trust"
#  slot. Output: "<slot>.pub" and the signed "<slot>.es3" file
#  (ES3 signing header + slot/key data).
##########################################################################

add_executable(es3getpubsign
   src/main.c
)

target_link_libraries(es3getpubsign PRIVATE
   tnp
   mbedtls
   adler32
)

if(WIN32)
   # GetUserName() lives in advapi32
   target_link_libraries(es3getpubsign PRIVATE advapi32)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
   target_compile_options(es3getpubsign PRIVATE -Wall -Wextra)
   # snprintf can theoretically truncate the path buffers, this is intended
   target_compile_options(es3getpubsign PRIVATE -Wno-format-truncation)
elseif(MSVC)
   target_compile_options(es3getpubsign PRIVATE /W4)
endif()
