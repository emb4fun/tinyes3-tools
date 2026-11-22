##########################################################################
#  es3slotlist
#
#  Get the list of the available key slots from the ES3 signing
#  server via the RPC protocol (UDP, port 54322).
##########################################################################

add_executable(es3slotlist
   src/main.c
)

target_link_libraries(es3slotlist PRIVATE
   tnp
   mbedtls
)

if(WIN32)
   # GetUserName() lives in advapi32
   target_link_libraries(es3slotlist PRIVATE advapi32)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
   target_compile_options(es3slotlist PRIVATE -Wall -Wextra)
   # snprintf can theoretically truncate the path buffers, this is intended
   target_compile_options(es3slotlist PRIVATE -Wno-format-truncation)
elseif(MSVC)
   target_compile_options(es3slotlist PRIVATE /W4)
endif()
