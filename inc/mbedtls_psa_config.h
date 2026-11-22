/**************************************************************************
*  Copyright (c) 2026 by Michael Fischer (www.emb4fun.de).
*  All rights reserved.
*
*  Redistribution and use in source and binary forms, with or without 
*  modification, are permitted provided that the following conditions 
*  are met:
*  
*  1. Redistributions of source code must retain the above copyright 
*     notice, this list of conditions and the following disclaimer.
*
*  2. Redistributions in binary form must reproduce the above copyright
*     notice, this list of conditions and the following disclaimer in the 
*     documentation and/or other materials provided with the distribution.
*
*  3. Neither the name of the author nor the names of its contributors may 
*     be used to endorse or promote products derived from this software 
*     without specific prior written permission.
*
*  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
*  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
*  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
*  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
*  THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
*  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
*  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS 
*  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED 
*  AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
*  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF 
*  THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
*  SUCH DAMAGE.
*
***************************************************************************
*  History:
*
*  21.11.2026  mifi  First Version, based on mbedTLS 4.1.2.
*
*  Custom TF-PSA-Crypto configuration for the tinyes3 tools.
*  This file is used as TF_PSA_CRYPTO_CONFIG_FILE and replaces the
*  default "psa/crypto_config.h" of TF-PSA-Crypto.
*
*  It contains all crypto modules (MBEDTLS_*_C) needed by the tools
*  and the PSA wants (PSA_WANT_*) for the algorithms and key types.
**************************************************************************/
#if !defined(__MBEDTLS_PSA_CONFIG_H__)
#define __MBEDTLS_PSA_CONFIG_H__

/**************************************************************************
*  Crypto modules (formerly part of the mbedTLS config, in mbedTLS 4.x
*  these modules are provided by TF-PSA-Crypto)
**************************************************************************/

/* PSA crypto core, required */
#define MBEDTLS_PSA_CRYPTO_C

/* Platform layer, required on Windows */
#define MBEDTLS_PLATFORM_C

/* Entropy source for the random generator, required for psa_generate_key */
#define MBEDTLS_PSA_BUILTIN_GET_ENTROPY

/*
 * DRBG for the PSA random generator
 */
#define MBEDTLS_CTR_DRBG_C

/* ASN.1 / PEM / Base64, required for the key import and export */
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_PEM_WRITE_C

/* PK module, required for the PEM key files (id_es3 / id_es3.pub) */
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_PARSE_EC_COMPRESSED
#define MBEDTLS_PK_WRITE_C

/* MD module, required for the message digests */
#define MBEDTLS_MD_C

/* Filesystem IO, required for mbedtls_pk_parse_keyfile() */
#define MBEDTLS_FS_IO

/**************************************************************************
*  PSA wants
**************************************************************************/

/*
 * Hash algorithms
 */
#define PSA_WANT_ALG_MD5                        1
#define PSA_WANT_ALG_SHA_256                    1

/*
 * AES / ECB, required by the CTR_DRBG of the PSA random generator
 */
#define PSA_WANT_KEY_TYPE_AES                   1
#define PSA_WANT_ALG_ECB_NO_PADDING             1

/*
 * ECC / ECDSA
 */
#define PSA_WANT_ALG_ECDSA                      1

#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC    1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE 1

#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY_BASIC  1
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY_IMPORT 1
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY_EXPORT 1

#define PSA_WANT_ECC_SECP_R1_256                1

#endif /* !__MBEDTLS_PSA_CONFIG_H__ */

/*** EOF ***/