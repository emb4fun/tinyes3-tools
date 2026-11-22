##########################################################################
#  es3discover
#
#  Search for Embedded Secure Signing Server (ES3) in the local
#  network via the TNP UDP discovery protocol.
#
#  Note: The TNP discovery library (libtnp.a) is defined in
#        src/CMakeLists.txt and shared with es3getpub, es3sign,
#        es3slotlist and es3getpubsign.
##########################################################################

#--------------------------------------------------------------------------
#  es3discover tool
#--------------------------------------------------------------------------
add_executable(es3discover
   src/main.c
)

target_link_libraries(es3discover PRIVATE
   tnp
)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
   target_compile_options(es3discover PRIVATE -Wall -Wextra)
elseif(MSVC)
   target_compile_options(es3discover PRIVATE /W4)
endif()
