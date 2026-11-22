/**************************************************************************
*  Copyright (c) 2021-2026 by Michael Fischer (www.emb4fun.de).
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
*  Custom Mbed TLS configuration for the tinyes3 tools.
*  This file is used as MBEDTLS_CONFIG_FILE.
*
*  NOTE: Since mbedTLS 4.x the crypto modules (PK, PEM, Base64, MD,
*        PSA Crypto, ...) are provided by TF-PSA-Crypto and are
*        configured in "mbedtls_psa_config.h"
*        (TF_PSA_CRYPTO_CONFIG_FILE). The main Mbed TLS library
*        (TLS, X.509) is not used by the tinyes3 tools at all.
**************************************************************************/
#if !defined(__MBEDTLS_CONF_H__)
#define __MBEDTLS_CONF_H__

/*
 * Mbed TLS 4.x configuration format
 */
#define MBEDTLS_CONFIG_VERSION   0x04000000

/*
 * No module of the main Mbed TLS library (TLS, X.509, ...) is
 * needed by the tinyes3 tools. All crypto modules are enabled in
 * "mbedtls_psa_config.h" instead.
 */

#endif /* !__MBEDTLS_CONF_H__ */

/*** EOF ***/