/**************************************************************************
*  Copyright (c) 2021-2024 by Michael Fischer (www.emb4fun.de).
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
**************************************************************************/
#define __MAIN_C__

/*=======================================================================*/
/*  Includes                                                             */
/*=======================================================================*/
#include <winsock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include "stdint.h"

#include "mbedtls/platform.h"
#include "mbedtls/base64.h"
#include "mbedtls/md5.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

/*=======================================================================*/
/*  All Structures and Common Constants                                  */
/*=======================================================================*/

#define VERSION         "1.20"

#define GOTO_END(_a)    { rc = _a; goto end; }

/* The key should not overwrite */
#define NOT_OVERWRITE   1

/*=======================================================================*/
/*  Definition of all local Data                                         */
/*=======================================================================*/

static char    UserName[_MAX_PATH];
static char    ComputerName[_MAX_PATH];
static char    HomePath[_MAX_PATH];
static char    ES3Folder[_MAX_PATH];
static char    PrivFilename[_MAX_PATH];
static char    PubFilename[_MAX_PATH];

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

/*=======================================================================*/
/*  Definition of all local Procedures                                   */
/*=======================================================================*/

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
   printf("(c) 2021 by Michael Fischer (www.emb4fun.de)\n");
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
/*  Return: none                                                         */
/*************************************************************************/
static int OutputFingerprintOnly (void)
{
   int     rc = -1;
   int     Index;
   FILE  *hFile;
   DWORD  dReadCnt;
   char    Buffer[1024];

   hFile = fopen(PubFilename, "rb");
   if (NULL == hFile)
   {
      printf("Public key \"%s\" not found\n", PubFilename);       
   }
   else
   {
      dReadCnt = fread(Buffer, sizeof(BYTE), sizeof(Buffer), hFile);
      fclose(hFile);
      
      if ((dReadCnt != 0) && (dReadCnt < (sizeof(Buffer) - 1)))
      {
         /* Add termination to the string */
         Buffer[dReadCnt] = 0;
         
         rc = Fingerprint(Buffer);
         if (0 == rc)
         {
            /* Output fingerprint */   
            printf("The public key fingerprint is:\n"); 
            printf("%s ", KeyType);
   
            for (Index = 0; Index < sizeof(KeyMD5Sum); Index++)
            {
               printf("%02X", KeyMD5Sum[Index]);
            }
            printf(" %s\n\n", KeyNameComputer);
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
   uint8_t            Temp[512];  
   uint8_t          *pPtr;
   uint8_t          *pStart;
   uint8_t          *pEnd;
   uint8_t          *buf = NULL;
   uint8_t          *p;

   /* Copy key */   
   _snprintf(Temp, sizeof(Temp), "%s", pKey);

   /* Clear data first */
   memset(KeyType, 0x00, sizeof(KeyType));   
   memset(KeyMD5Sum, 0x00, sizeof(KeyMD5Sum));
   memset(KeyNameComputer, 0x00, sizeof(KeyNameComputer));
   
   /* Check type */
   pStart = strstr(Temp, "es3-nistp256");
   if (pStart != NULL)
   {
      _snprintf(KeyType, sizeof(KeyType), "NIST P-256");
      pStart += 12;
   }   
   
   /* Jump over spaces */
   while (0x20 == *pStart)
   {
      pStart++;
   }
   
   /* Find end of data */
   pEnd = strstr(pStart, " ");
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
   rc = mbedtls_base64_decode(NULL, 0, &len, pStart, strlen(pStart));   
   if (rc == MBEDTLS_ERR_BASE64_INVALID_CHARACTER) GOTO_END(-1);

   /* Allocate decode buffer */   
   buf = mbedtls_calloc(1, len);
   if (NULL == buf) GOTO_END(-2);

   /* Decode now */
   rc = mbedtls_base64_decode(buf, len, &len, pStart, strlen(pStart));
   if (rc != 0) GOTO_END(-3);
   
   /* 
    * At this point buf with len contains the raw key data.
    */
    
   /* Create MD5 hash of decoded data */    
   rc = mbedtls_md5_ret(buf, len, KeyMD5Sum);
   if (rc != 0) GOTO_END(-4);

   /* Check if this is a valid key */
   p = buf;
   rc = mbedtls_pk_parse_subpubkey(&p,  p + len, &ctx);
   if (rc != 0) GOTO_END(-5);
   
   /* 
    * At this point we have a valid ECC key.
    */
    
   /* Find user and computer name. pEnd is based on Temp */
   pStart = pEnd; /* Set the new start */
   pEnd   = Temp + strlen(pKey);
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
      _snprintf(KeyNameComputer, sizeof(KeyNameComputer), "%s", pStart);
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
      mbedtls_free(buf);
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
   DWORD  dAttr;
   FILE  *hFile;
   DWORD  dWriteCnt;

   /* Check if the "es3" folder must be created */
   dAttr = GetFileAttributes(ES3Folder);  
   if (0xFFFFFFFF == dAttr)
   {
      /* Directory not available */
      ok = CreateDirectory(ES3Folder, NULL);
      if (ok != 1) GOTO_END(-1);
   } 

   /* 
    * Save private key
    */   
   hFile = fopen(PrivFilename, "wb");
   if (NULL == hFile) GOTO_END(-1);
   
   dWriteCnt = fwrite(KeyPriv, sizeof(BYTE), strlen(KeyPriv), hFile);
   fclose(hFile);
   if (dWriteCnt != strlen(KeyPriv)) GOTO_END(-1);

   /* 
    * Save public key
    */   
   hFile = fopen(PubFilename, "wb");
   if (NULL == hFile) GOTO_END(-1);
   
   dWriteCnt = fwrite(KeyPub, sizeof(BYTE), strlen(KeyPub), hFile);
   fclose(hFile);
   if (dWriteCnt != strlen(KeyPub)) GOTO_END(-1);

   /* 
    * Output fingerprint 
    */   
   printf("The public key fingerprint is:\n"); 
   printf("%s ", KeyType);
   
   for (Index = 0; Index < sizeof(KeyMD5Sum); Index++)
   {
      printf("%02X", KeyMD5Sum[Index]);
   }
   printf(" %s\n\n", KeyNameComputer);
      
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
   int                      rc;
   mbedtls_pk_context       pk;
   mbedtls_entropy_context  entropy;
   mbedtls_ctr_drbg_context ctr_drbg;
   mbedtls_ecp_group_id     grp_id = MBEDTLS_ECP_DP_SECP256R1;
   uint8_t                *pPtr;
   uint8_t                *pEnd;
   DWORD                   dAttr;
   int                      Index;
   char                     c;
   
   /* Prepare key generation */
   mbedtls_pk_init(&pk);
   mbedtls_ctr_drbg_init(&ctr_drbg);
   mbedtls_entropy_init(&entropy);

   /* Seed the random generator */
   rc =  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) "TinyES3keygen", 13);
   if (rc != 0) GOTO_END(-1); 
   
   /* Generate the key */
   rc = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
   if (rc != 0) GOTO_END(-2);

   rc = mbedtls_ecp_gen_key(grp_id, mbedtls_pk_ec(pk), mbedtls_ctr_drbg_random, &ctr_drbg);
   if (rc != 0) GOTO_END(-3);
   
   /* "Convert" private key */
   rc = mbedtls_pk_write_key_pem(&pk, KeyPriv, sizeof(KeyPriv));
   if (rc != 0) GOTO_END(-4);
   
   /* "Convert" public key */
   rc = mbedtls_pk_write_pubkey_pem(&pk, KeyPub, sizeof(KeyPub));
   if (rc != 0) GOTO_END(-5);

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
   pEnd = strstr(pPtr, "-----END PUBLIC KEY-----");
   if (NULL == pEnd) GOTO_END(-6); 
   *pEnd = 0;
   
   /*
    * 3. Remove 0x0A from the end
    */
   pEnd--;
   while(0x0A == *pEnd)
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
   _snprintf(KeyPub, sizeof(KeyPub), "es3-nistp256 %s %s@%s", 
             TempPub, UserName, ComputerName);
             
   /* Create fingerprint for later use */             
   rc = Fingerprint(KeyPub);             
   if (rc != 0) GOTO_END(-7);
             
   /* Clear temp data */             
   memset(TempPub, 0x00, sizeof(TempPub));

   printf("Successful generation of a private/public es3 key pair.\n\n"); 

   /* Check if file already exists */
   dAttr = GetFileAttributes(PrivFilename);  
   if (dAttr != 0xFFFFFFFF)
   {
      /* File already exists */  
      printf("\"%s\" already exists.\n", PrivFilename);
      printf("Overwrite (y/n)?");
      
      /* Check if the file should be overwrite */   
      if (scanf("%c", &c) != 1) GOTO_END(-8);
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
   mbedtls_ctr_drbg_free(&ctr_drbg);
   mbedtls_entropy_free(&entropy);

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
   int     rc = -1;
   DWORD  dSize;
   BOOL   ok;

   /* Clear data first */   
   memset(UserName, 0x00, sizeof(UserName));
   memset(ComputerName, 0x00, sizeof(ComputerName));
   memset(HomePath, 0x00, sizeof(HomePath));
   memset(ES3Folder, 0x00, sizeof(ES3Folder));
   memset(PrivFilename, 0x00, sizeof(PrivFilename));
   memset(PubFilename, 0x00, sizeof(PubFilename));

   /* Get User name */
   dSize = sizeof(UserName);
   ok = GetUserName(UserName, &dSize);
   if (1 == ok)
   {
      /* Get Computer name */   
      dSize = sizeof(ComputerName);
      ok = GetComputerName(ComputerName, &dSize);
      if (1 == ok)
      {
         /* Get Home path */
         dSize = ExpandEnvironmentStrings("%HOMEPATH%", HomePath, sizeof(HomePath));
         if ((dSize > 0) && (dSize < sizeof(HomePath)))
         {
            /* Build ES3 folder */
            _snprintf(ES3Folder, sizeof(ES3Folder), "C:%s\\.es3", HomePath);
            
            _snprintf(PrivFilename, sizeof(PrivFilename), "%s\\id_es3", ES3Folder);
            _snprintf(PubFilename, sizeof(PubFilename), "%s\\id_es3.pub", ES3Folder);

            rc = 0;
         }   
      }
   } 
   
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
