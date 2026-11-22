##########################################################################
#  adler32
#
#  Adler-32 checksum (based on zlib), used for the CRC in the
#  ES3 signing header (ES3_SIGN_HEAD).
##########################################################################

add_library(adler32 STATIC
   adler32.c
)

target_include_directories(adler32 PUBLIC
   ${CMAKE_CURRENT_SOURCE_DIR}
)
