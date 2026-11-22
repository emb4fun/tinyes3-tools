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
*  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
*  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
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
*  10.04.2021  mifi  First Version.
*  11.04.2021  mifi  Release version v1.00.
*  21.11.2026  mifi  Ported to MSYS2-UCRT64/Linux and mbedTLS 4.1.2.
**************************************************************************/
#define __MAIN_C__

/*=======================================================================*/
/*  Includes                                                             */
/*=======================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif

#include "psa/crypto.h"
#include "mbedtls/pk.h"
#include "mbedtls/base64.h"

/*=======================================================================*/
/*  All Structures and Common Constants                                  */
/*=======================================================================*/

#define VERSION         "2.00"

#define GOTO_END(_a)    { rc = _a; goto end; }

/* The key should not overwrite */
#define NOT_OVERWRITE   1

#if defined(_WIN32)
#define ES3_PATH_MAX   1024
#else
#define ES3_PATH_MAX   4096
#endif

/*=======================================================================*/
/*  Definition of all local Data                                         */
/*=======================================================================*/

static char    UserName[ES3_PATH_MAX];
static char    ComputerName[ES3_PATH_MAX];
static char    HomePath[ES3_PATH_MAX];
static char    ES3Folder[ES3_PATH_MAX];
static char    PrivFilename[ES3_PATH_MAX];
static char    PubFilename[ES3_PATH_MAX];

static uint8_t KeyPriv[512];
static uint8_t TempPub[512];
static uint8_t KeyPub[512];

static uint8_t KeyType[16];
static uint8_t KeyMD5Sum[16];
static uint8_t KeyNameComputer[64];

/*=======================================================================*/
/*  Definition of prototypes                                             */
/*=======================================================================*/

static int Fingerprint (uint8_t *pKey);

static int FileExists (const char *pPath);
static int FolderExists (const char *pPath);
static int CreateFolder (const char *pPath);

/*************************************************************************/
/*  FileExists                                                           */
/*                                                                       */
/*  In    : pPath                                                        */
/*  Out   : none                                                         */
/*  Return: 1 = file exists / 0 = file does not exist                    */
/*************************************************************************/
static int FileExists (const char *pPath)
{
   int ok = 0;

#if defined(_WIN32)
   if (GetFileAttributesA(pPath) != INVALID_FILE_ATTRIBUTES)
   {
      ok = 1;
   }
#else
   struct stat st;

   if (stat(pPath, &st) == 0)
   {
      ok = 1;
   }
#endif

   return(ok);
} /* FileExists */

/*************************************************************************/
/*  FolderExists                                                         */
/*                                                                       */
/*  In    : pPath                                                        */
/*  Out   : none                                                         */
/*  Return: 1 = folder exists / 0 = folder does not exist                */
/*************************************************************************/
static int FolderExists (const char *pPath)
{
   int ok = 0;

#if defined(_WIN32)
   DWORD dAttr = GetFileAttributesA(pPath);

   if ((dAttr != INVALID_FILE_ATTRIBUTES) && (dAttr & FILE_ATTRIBUTE_DIRECTORY))
   {
      ok = 1;
   }
#else
   struct stat st;

   if ((stat(pPath, &st) == 0) && S_ISDIR(st.st_mode))
   {
      ok = 1;
   }
#endif

   return(ok);
} /* FolderExists */

/*************************************************************************/
/*  CreateFolder                                                         */
/*                                                                       */
/*  In    : pPath                                                        */
/*  Out   : none                                                         */
/*  Return: 1 = OK / 0 = error                                           */
/*************************************************************************/
static int CreateFolder (const char *pPath)
{
   int ok;

#if defined(_WIN32)
   ok = (CreateDirectoryA(pPath, NULL) != 0) ? 1 : 0;
#else
   ok = (mkdir(pPath, 0755) == 0) ? 1 : 0;
#endif

   return(ok);
} /* CreateFolder */

/*************************************************************************/
/*  OutputStartMessage                                                   */
/*                                                                       */
/*  Output start message.                                                */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: none                                                         */
/*************************************************************************/
static void OutputStartMessage (void)
{
   printf("\n");
   printf("es3keygen v%s compiled "__DATE__" "__TIME__"\n", VERSION);
   printf("(c) 2021-2026 by Michael Fischer (www.emb4fun.de)\n");
   printf("\n");

} /* OutputStartMessage */

/*************************************************************************/
/*  OutputUsage                                                          */
/*                                                                       */
/*  Output "usage" message.                                              */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: none                                                         */
/*************************************************************************/
static void OutputUsage (void)
{
  printf("Usage: es3keygen [-v] [-f]\n");
  printf("\n");
  printf("  -v   Show version information only\n");
  printf("  -f   Show public key fingerprint only\n");

} /* OutputUsage */

/*************************************************************************/
/*  OutputFingerprintOnly                                                */
/*                                                                       */
/*  Output fingerprint of the public key.                                */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: 0 = OK / error cause                                         */
/*************************************************************************/
static int OutputFingerprintOnly (void)
{
   int     rc = -1;
   int     Index;
   FILE  *hFile;
   size_t  dReadCnt;
   char    Buffer[1024];

   hFile = fopen(PubFilename, "rb");
   if (NULL == hFile)
   {
      printf("Public key \"%s\" not found\n", PubFilename);
   }
   else
   {
      dReadCnt = fread(Buffer, sizeof(char), sizeof(Buffer), hFile);
      fclose(hFile);

      if ((dReadCnt != 0) && (dReadCnt < (sizeof(Buffer) - 1)))
      {
         /* Add termination to the string */
         Buffer[dReadCnt] = 0;

         rc = Fingerprint((uint8_t *)Buffer);
         if (0 == rc)
         {
            /* Output fingerprint */
            printf("The public key fingerprint is:\n");
            printf("%s ", (char *)KeyType);

            for (Index = 0; Index < (int)sizeof(KeyMD5Sum); Index++)
            {
               printf("%02X", KeyMD5Sum[Index]);
            }
            printf(" %s\n\n", (char *)KeyNameComputer);
         }
         else
         {
            /* Error */
            printf("Public key error %d\n", rc);
         }
      }
   }

   return(rc);
} /* OutputFingerprintOnly */

/*************************************************************************/
/*  Fingerprint                                                          */
/*                                                                       */
/*  Calculate the fingerprint of the given public key.                   */
/*                                                                       */
/*  In    : pKey                                                         */
/*  Out   : none                                                         */
/*  Return: 0 = OK / error cause                                         */
/*************************************************************************/
static int Fingerprint (uint8_t *pKey)
{
   int                rc = -1;
   mbedtls_pk_context ctx;
   size_t             len;
   size_t             hash_len = 0;
   uint8_t            Temp[512];
   uint8_t          *pPtr;
   uint8_t          *pStart;
   uint8_t          *pEnd;
   uint8_t          *buf = NULL;

   /* Copy key */
   snprintf((char *)Temp, sizeof(Temp), "%s", (char *)pKey);

   /* Clear data first */
   memset(KeyType, 0x00, sizeof(KeyType));
   memset(KeyMD5Sum, 0x00, sizeof(KeyMD5Sum));
   memset(KeyNameComputer, 0x00, sizeof(KeyNameComputer));

   /* Check type */
   pStart = (uint8_t *)strstr((char *)Temp, "es3-nistp256");
   if (pStart != NULL)
   {
      snprintf((char *)KeyType, sizeof(KeyType), "NIST P-256");
      pStart += 12;
   }
   else
   {
      /* Unknown key type */
      return(-1);
   }

   /* Jump over spaces */
   while (0x20 == *pStart)
   {
      pStart++;
   }

   /* Find end of data */
   pEnd = (uint8_t *)strstr((char *)pStart, " ");
   if (pEnd != NULL)
   {
      *pEnd = 0;
   }

   /* Convert '-' to 0x0A */
   pPtr = pStart;
   while (*pPtr != 0)
   {
      if ('-' == *pPtr)
      {
         *pPtr = 0x0A;
      }
      pPtr++;
   }

   mbedtls_pk_init(&ctx);

   /* Dummy decode to get size of decode buffer */
   rc = mbedtls_base64_decode(NULL, 0, &len, pStart, strlen((char *)pStart));
   if (rc == MBEDTLS_ERR_BASE64_INVALID_CHARACTER) GOTO_END(-1);

   /* Allocate decode buffer */
   buf = calloc(1, len);
   if (NULL == buf) GOTO_END(-2);

   /* Decode now */
   rc = mbedtls_base64_decode(buf, len, &len, pStart, strlen((char *)pStart));
   if (rc != 0) GOTO_END(-3);

   /*
    * At this point buf with len contains the raw key data.
    */

   /* Create MD5 hash of decoded data */
   rc = psa_hash_compute(PSA_ALG_MD5, buf, len,
                         KeyMD5Sum, sizeof(KeyMD5Sum), &hash_len);
   if (rc != PSA_SUCCESS) GOTO_END(-4);

   /* Check if this is a valid key */
   rc = mbedtls_pk_parse_public_key(&ctx, buf, len);
   if (rc != 0) GOTO_END(-5);

   /*
    * At this point we have a valid ECC key.
    */

   /* Find user and computer name. pEnd is based on Temp */
   pStart = pEnd; /* Set the new start */
   pEnd   = Temp + strlen((char *)pKey);
   if ((pStart != NULL) && (pStart < pEnd))
   {
      /* Jump to the name@cumputer */
      pStart++;

      /* Jump over spaces */
      while (0x20 == *pStart)
      {
         pStart++;
      }

      /* This must be the user and computer name */
      snprintf((char *)KeyNameComputer, sizeof(KeyNameComputer), "%s", (char *)pStart);
      rc = 0;
   }
   else
   {
      /* Error */
      rc = -6;
   }

end:

   /* Free buffer if available */
   if (buf != NULL)
   {
      free(buf);
   }

   /* Clear data */
   memset(Temp, 0x00, sizeof(Temp));

   /* Free the mbedTLS content */
   mbedtls_pk_free(&ctx);

   return(rc);
} /* Fingerprint */

/*************************************************************************/
/*  SaveKey                                                              */
/*                                                                       */
/*  Save the private and public key to the disk.                         */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: 0 = OK / error cause                                         */
/*************************************************************************/
static int SaveKey (void)
{
   int     rc = -1;
   int     ok;
   int     Index;
   FILE  *hFile;
   size_t  dWriteCnt;

   /* Check if the "es3" folder must be created */
   if (0 == FolderExists(ES3Folder))
   {
      /* Directory not available */
      ok = CreateFolder(ES3Folder);
      if (ok != 1) GOTO_END(-1);
   }

   /*
    * Save private key
    */
   hFile = fopen(PrivFilename, "wb");
   if (NULL == hFile) GOTO_END(-1);

   dWriteCnt = fwrite(KeyPriv, sizeof(char), strlen((char *)KeyPriv), hFile);
   fclose(hFile);
   if (dWriteCnt != strlen((char *)KeyPriv)) GOTO_END(-1);

   /*
    * Save public key
    */
   hFile = fopen(PubFilename, "wb");
   if (NULL == hFile) GOTO_END(-1);

   dWriteCnt = fwrite(KeyPub, sizeof(char), strlen((char *)KeyPub), hFile);
   fclose(hFile);
   if (dWriteCnt != strlen((char *)KeyPub)) GOTO_END(-1);

   /*
    * Output fingerprint
    */
   printf("The public key fingerprint is:\n");
   printf("%s ", (char *)KeyType);

   for (Index = 0; Index < (int)sizeof(KeyMD5Sum); Index++)
   {
      printf("%02X", KeyMD5Sum[Index]);
   }
   printf(" %s\n\n", (char *)KeyNameComputer);

   printf("Your private key has been saved in: \"%s\"\n", PrivFilename);
   printf("Your public key has been saved in: \"%s\"\n", PubFilename);

   /* No error */
   rc = 0;

end:

   return(rc);
} /* SaveKey */

/*************************************************************************/
/*  CreateKeyPair                                                        */
/*                                                                       */
/*  Create the private and public key.                                   */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: 0 = OK / error cause                                         */
/*************************************************************************/
static int CreateKeyPair (void)
{
   int                   rc;
   psa_status_t         status;
   psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
   mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
   mbedtls_pk_context   pk;
   uint8_t            *pPtr;
   uint8_t            *pEnd;
   int                  Index;
   char                 c;

   /*
    * Generate the key (NIST P-256)
    */
   psa_set_key_type(&attributes,
                    PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
   psa_set_key_bits(&attributes, 256);
   psa_set_key_usage_flags(&attributes,
                           PSA_KEY_USAGE_SIGN_HASH |
                           PSA_KEY_USAGE_VERIFY_HASH |
                           PSA_KEY_USAGE_EXPORT);
   psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA_ANY);

   status = psa_generate_key(&attributes, &key_id);
   if (status != PSA_SUCCESS) GOTO_END(-1);

   /* Copy the PSA key into a PK context */
   mbedtls_pk_init(&pk);
   rc = mbedtls_pk_copy_from_psa(key_id, &pk);
   if (rc != 0) GOTO_END(-2);

   /*
    * Convert the private key into a PEM string
    */
   rc = mbedtls_pk_write_key_pem(&pk, KeyPriv, sizeof(KeyPriv));
   if (rc != 0) GOTO_END(-3);

   /*
    * Convert the public key into a PEM string
    */
   rc = mbedtls_pk_write_pubkey_pem(&pk, KeyPub, sizeof(KeyPub));
   if (rc != 0) GOTO_END(-4);

   /*
    * Convert public key
    *
    * "es3-nistp256 keydata user@computer"
    */

   /*
    * 1. Remove "-----BEGIN PUBLIC KEY-----"
    */
   pPtr = &KeyPub[26];
   while (0x0A == *pPtr) pPtr++;

   /*
    * 2. Remove "-----END PUBLIC KEY-----"
    */
   pEnd = (uint8_t *)strstr((char *)pPtr, "-----END PUBLIC KEY-----");
   if (NULL == pEnd) GOTO_END(-5);
   *pEnd = 0;

   /*
    * 3. Remove 0x0A from the end
    */
   pEnd--;
   while (0x0A == *pEnd)
   {
      *pEnd = 0;
      pEnd--;
   }

   /*
    * 4. Copy data and replace 0x0A by '-'
    */
   Index = 0;
   while (*pPtr != 0)
   {
      if (0x0A == *pPtr)
      {
         TempPub[Index++] = '-';
      }
      else
      {
         TempPub[Index++] = *pPtr;
      }
      pPtr++;
   }
   TempPub[Index] = 0;

   /*
    * 5. Create new key
    */
   snprintf((char *)KeyPub, sizeof(KeyPub), "es3-nistp256 %s %s@%s",
            (char *)TempPub, UserName, ComputerName);

   /* Create fingerprint for later use */
   rc = Fingerprint(KeyPub);
   if (rc != 0) GOTO_END(-6);

   /* Clear temp data */
   memset(TempPub, 0x00, sizeof(TempPub));

   printf("Successful generation of a private/public es3 key pair.\n\n");

   /* Check if file already exists */
   if (1 == FileExists(PrivFilename))
   {
      /* File already exists */
      printf("\"%s\" already exists.\n", PrivFilename);
      printf("Overwrite (y/n)?");

      /* Check if the file should be overwrite */
      if (scanf("%c", &c) != 1) GOTO_END(-7);
      if ((c != 'y') && (c != 'Y')) GOTO_END(NOT_OVERWRITE);

      /* 'y' or 'Y' was pressed */
      printf("\n");
   }

end:

   /* Data will be cleared in case of an error */
   if (rc != 0)
   {
      memset(KeyPriv, 0x00, sizeof(KeyPriv));
      memset(TempPub, 0x00, sizeof(TempPub));
      memset(KeyPub , 0x00, sizeof(KeyPub));
   }

   /* Free the mbedTLS content */
   mbedtls_pk_free(&pk);
   psa_destroy_key(key_id);

   return(rc);
} /* CreateKeyPair */

/*************************************************************************/
/*  GetEnvironemnt                                                       */
/*                                                                       */
/*  Retrieve infos like user, computer name and home path.               */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: 0 = OK / error cause                                         */
/*************************************************************************/
static int GetEnvironemnt (void)
{
   int   rc = -1;

   /* Clear data first */
   memset(UserName, 0x00, sizeof(UserName));
   memset(ComputerName, 0x00, sizeof(ComputerName));
   memset(HomePath, 0x00, sizeof(HomePath));
   memset(ES3Folder, 0x00, sizeof(ES3Folder));
   memset(PrivFilename, 0x00, sizeof(PrivFilename));
   memset(PubFilename, 0x00, sizeof(PubFilename));

#if defined(_WIN32)
   {
      DWORD dSize;
      int   ok;

      /* Get User name */
      dSize = sizeof(UserName);
      ok = GetUserNameA(UserName, &dSize);
      if (ok == 1)
      {
         /* Get Computer name */
         dSize = sizeof(ComputerName);
         ok = GetComputerNameA(ComputerName, &dSize);
         if (ok == 1)
         {
            /* Get Home path */
            if (ExpandEnvironmentStringsA("%HOMEPATH%", HomePath, sizeof(HomePath)) > 0)
            {
               /* Build ES3 folder */
               snprintf(ES3Folder, sizeof(ES3Folder), "C:%s\\.es3", HomePath);

               snprintf(PrivFilename, sizeof(PrivFilename), "%s\\id_es3", ES3Folder);
               snprintf(PubFilename, sizeof(PubFilename), "%s\\id_es3.pub", ES3Folder);

               rc = 0;
            }
         }
      }
   }
#else
   {
      char *pEnv;

      /* Get User name */
      pEnv = getenv("USER");
      if (pEnv == NULL)
      {
         pEnv = getenv("LOGNAME");
      }
      if (pEnv != NULL)
      {
         snprintf(UserName, sizeof(UserName), "%s", pEnv);

         /* Get Computer name */
         if (gethostname(ComputerName, sizeof(ComputerName)) == 0)
         {
            /* Get Home path */
            pEnv = getenv("HOME");
            if (pEnv != NULL)
            {
               snprintf(HomePath, sizeof(HomePath), "%s", pEnv);

               /* Build ES3 folder */
               snprintf(ES3Folder, sizeof(ES3Folder), "%s/.es3", HomePath);

               snprintf(PrivFilename, sizeof(PrivFilename), "%s/id_es3", ES3Folder);
               snprintf(PubFilename, sizeof(PubFilename), "%s/id_es3.pub", ES3Folder);

               rc = 0;
            }
         }
      }
   }
#endif

   return(rc);
} /* GetEnvironemnt */

/*=======================================================================*/
/*  All code exported                                                    */
/*=======================================================================*/

/*************************************************************************/
/*  main                                                                 */
/*                                                                       */
/*  In    : argc, argv                                                   */
/*  Out   : none                                                         */
/*  Return: 0 = OK / error cause                                         */
/*************************************************************************/
int main (int argc, char **argv)
{
   int rc;
   int Index;
   int CmdUnknown     = 0;
   int CmdVersion     = 0;
   int CmdFingerprint = 0;

   /*
    * Output start message
    */
   OutputStartMessage();

   /*
    * Check arguments if available
    */
   if (argc > 1)
   {
      for (Index = 1; Index < argc; Index++)
      {
         if      (0 == strcmp(argv[Index], "-v"))
         {
            CmdVersion = 1;
         }
         else if (0 == strcmp(argv[Index], "-f"))
         {
            CmdFingerprint = 1;
         }
         else
         {
            CmdUnknown = 1;
         }
      }
   }

   /* Ups, found an unknown command */
   if (1 == CmdUnknown)
   {
      OutputUsage();
      exit(0);
   }

   /* Version information requested */
   if (1 == CmdVersion)
   {
      /* Only OutputStartMessage was needed */
      exit(0);
   }

   /*
    * Initialize the crypto subsystem (mbedTLS 4.x / PSA)
    */
   rc = psa_crypto_init();
   if (rc != PSA_SUCCESS)
   {
      printf("Error, could not initialize the crypto subsystem.\n");
      GOTO_END(-1);
   }

   /*
    * Retrieve infos like user, computer name and home path
    */
   rc = GetEnvironemnt();
   if (rc != 0)
   {
      printf("Error, could not retrieve environment variables.\n");
      GOTO_END(-1);
   }

   /*
    * Check for fingerprint command only
    */
   if (1 == CmdFingerprint)
   {
      OutputFingerprintOnly();
      exit(0);
   }

   /*
    * Create key pair
    */
   rc = CreateKeyPair();
   if (NOT_OVERWRITE == rc) GOTO_END(0);   /* Key should not overwrite */

   if (rc != 0)
   {
      printf("Error, could not create private/public key pair.\n");
      GOTO_END(-1);
   }

   /*
    * Save key
    */
   rc = SaveKey();
   if (rc != 0)
   {
      printf("Error, could not save private/public key pair.\n");
      GOTO_END(-1);
   }

end:

   /* Delete key data */
   memset(KeyPriv, 0x00, sizeof(KeyPriv));
   memset(TempPub, 0x00, sizeof(TempPub));
   memset(KeyPub , 0x00, sizeof(KeyPub));

   memset(KeyType, 0x00, sizeof(KeyType));
   memset(KeyMD5Sum, 0x00, sizeof(KeyMD5Sum));
   memset(KeyNameComputer, 0x00, sizeof(KeyNameComputer));

   return(rc);
} /* main */

/*** EOF ***/
