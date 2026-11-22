##########################################################################
#  es3verify
#
#  Verify a signed ES3 file (<file>.es3) locally against a public
#  key file (<slot>.pub). No network or server connection is needed.
##########################################################################

add_executable(es3verify
   src/main.c
)

target_include_directories(es3verify PRIVATE
   ${PROJECT_SOURCE_DIR}/inc
)

target_link_libraries(es3verify PRIVATE
   mbedtls
   adler32
)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
   target_compile_options(es3verify PRIVATE -Wall -Wextra)
   # snprintf can theoretically truncate the path buffers, this is intended
   target_compile_options(es3verify PRIVATE -Wno-format-truncation)
elseif(MSVC)
   target_compile_options(es3verify PRIVATE /W4)
endif()
