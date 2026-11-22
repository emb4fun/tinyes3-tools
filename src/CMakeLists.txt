##########################################################################
#  tnp
#
#  TNP UDP discovery support library (src/tnp.c), shared by all
#  tools which need to find the ES3 server in the network:
#  es3discover, es3getpub, es3sign, es3slotlist, es3getpubsign.
##########################################################################

add_library(tnp STATIC
   tnp.c
)

target_include_directories(tnp PUBLIC
   ${PROJECT_SOURCE_DIR}/inc
)

if(WIN32)
   target_link_libraries(tnp PUBLIC ws2_32)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
   target_compile_options(tnp PRIVATE -Wall -Wextra)
elseif(MSVC)
   target_compile_options(tnp PRIVATE /W4)
endif()
