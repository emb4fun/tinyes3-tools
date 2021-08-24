/**************************************************************************
*  Copyright (c) 2021 by Michael Fischer (www.emb4fun.de).
*  All rights reserved.
*
*  Redistribution and use in source and binary forms, with or without 
*  modification, are permitted provided that the following conditions 
*  are met:
*  
*  1. Redistributions of source code must retain the above copyright 
*     notice, this list of conditions and the following disclaimer.
*  2. Redistributions in binary form must reproduce the above copyright
*     notice, this list of conditions and the following disclaimer in the 
*     documentation and/or other materials provided with the distribution.
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
*  17.04.2021  mifi  First Version, release version v1.00.
*  08.05.2021  mifi  Reduce ES3_SIGN_HEAD size.
**************************************************************************/
#define __MAIN_C__

/*=======================================================================*/
/*  Includes                                                             */
/*=======================================================================*/
#include <windows.h>
#include <stdio.h>
#include "stdint.h"
#include "adler32.h"
#include "es3_sign.h"

#include "mbedtls/platform.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"

/*=======================================================================*/
/*  All Structures and Common Constants                                  */
/*=======================================================================*/

#define VERSION         "1.10"

#define GOTO_END(_a)    { rc = _a; goto end; }

#define MAX_IMAGE_SIZE  (4*1024*1024)

#define FILE_NAME_SIZE  (_MAX_PATH-1)

/*=======================================================================*/
/*  Definition of all local Data                                         */
/*=======================================================================*/

static char KeyName[FILE_NAME_SIZE+1];
static char FileName[FILE_NAME_SIZE+1];

static BYTE InImage[MAX_IMAGE_SIZE];

/*=======================================================================*/
/*  Definition of prototypes                                             */
/*=======================================================================*/

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
   printf("es3verify v%s compiled "__DATE__" "__TIME__"\n", VERSION);
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
  printf("Usage: es3verify -k key -f file\n");
  printf("\n");
  printf("  -k   Public key used to verify e.g. -k firefly.pub\n");
  printf("  -f   File to verify, e.g. -f firefly.es3\n");
  
} /* OutputUsage */

/*************************************************************************/
/*  VerifySignature                                                      */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: 0 = OK / error cause                                         */
/*************************************************************************/
static int VerifySignature (void)
{
   int                  rc;
   FILE               *hInFile;
   DWORD               dInFileSize;
   mbedtls_pk_context   pk;
   ES3_SIGN_HEAD      *pHeader;
   uint8_t            *pData;
   uint8_t              Hash[32];
   
   /*
    * Prepare key generation
    */
   mbedtls_pk_init(&pk);

   /* Read public key */   
   rc = mbedtls_pk_parse_public_keyfile(&pk, KeyName);
   if (rc != 0) 
   {
      printf("Error, \"%s\" is not a valid public key file.\n", KeyName);
      GOTO_END(-1);
   }
   
   /*
    * Check input file
    */   
   
   /* Check if input file is available */
   hInFile = fopen(FileName, "rb");
   if (NULL == hInFile)
   {
      printf("Error, input file \"%s\" not found\n", FileName);
      GOTO_END(-2);
   }

   /* Get size of input file */
   fseek(hInFile, 0, SEEK_END);
   dInFileSize = ftell(hInFile);
   fseek(hInFile, 0, SEEK_SET);
   
   /* Read input file data */
   if (dInFileSize > MAX_IMAGE_SIZE)
   {
      printf("Error, input file size > %d\n", MAX_IMAGE_SIZE);
      fclose(hInFile);
      GOTO_END(-3);
   }

   /* "Clear" InImage, read and close the file */
   memset(InImage, 0x00, sizeof(InImage));
   fread(InImage, 1, dInFileSize, hInFile); 
   fclose(hInFile);
   
   /*
    * Check whether this is a file which has an ES3 signature
    */
   pHeader = (ES3_SIGN_HEAD*)InImage;
   if( (ES3_HEAD_MAGIC1  == pHeader->dMagic1)      &&
       (ES3_HEAD_MAGIC2  == pHeader->dMagic2)      &&
       (ES3_HEAD_SIZEVER == pHeader->dSizeVersion) )
   {
      /* Check CRC */
      if (pHeader->dCRC32 == adler32(ADLER_START_VALUE, (uint8_t*)pHeader, sizeof(ES3_SIGN_HEAD) - sizeof(pHeader->dCRC32)))
      {
         /* Create hash */
         pData = &InImage[sizeof(ES3_SIGN_HEAD)];
         mbedtls_sha256_ret(pData, pHeader->dDataSize, Hash, 0);
         
         /* Check signature */
         rc = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, Hash, 0, pHeader->Signature, pHeader->bSigLen);
         if (0 == rc)
         {
            printf("The signature of the input file is valid.\n");
         }
         else
         {
            printf("Error, the signature of the input file is invalid.\n");
            rc = -4;
         }
      }
      else
      {
         printf("Error, input file \"%s\" has a defect CRC.\n", FileName);
         rc = -5;
      }
   }
   else
   {
      printf("Error, input file \"%s\" has not an ES3 signature.\n", FileName);
      rc = -6;
   }       
   
end:

   mbedtls_pk_free(&pk);

   return(rc);
} /* VerifySignature */


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
   int    rc = 0;
   int    Index;
   int    CmdUnknown  = 0;
   int    CmdVersion  = 0;
   int    CmdKey      = 0;
   int    CmdFile     = 0;
   FILE *hFile;
   
   
   /*
    * Output start message
    */
   OutputStartMessage();
   
   /* Clear data first */   
   memset(KeyName, 0x00, sizeof(KeyName));
   memset(FileName, 0x00, sizeof(FileName));
   
   /* 
    * Check arguments if available
    */
   if (argc > 1)
   {
      for (Index = 1; Index < argc; Index++)
      {
         /* Check slot name */
         if      (0 == strcmp(argv[Index], "-k"))
         {
            if ((Index + 1) < argc)
            {
               CmdKey = 1;   
               Index++;
               _snprintf(KeyName, FILE_NAME_SIZE, "%s", argv[Index]);
            }               
         }
         /* Check file name */
         else if (0 == strcmp(argv[Index], "-f"))
         {
            if ((Index + 1) < argc)
            {
               CmdFile = 1;   
               Index++;
               _snprintf(FileName, FILE_NAME_SIZE, "%s", argv[Index]);
            }               
         }
         /* Check version information only */
         else if (0 == strcmp(argv[Index], "-v"))
         {
            CmdVersion = 1;
         }
         else
         {
            /* Ups, unknown command */
            CmdUnknown = 1;
         }
      }
   }
   else
   {
      /* Error, no argument */
      CmdUnknown = 1;   
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

   /* Check if slot and file was used */
   if ((0 == CmdKey) || (0 == CmdFile))
   {
      /* Error */
      OutputUsage();
      GOTO_END(-1);
   }

   /* Check if key file is available */
   hFile = fopen(KeyName, "rb");
   if (NULL == hFile)
   {
      printf("Error, public key file \"%s\" not found\n", KeyName);
      GOTO_END(-2);
   }
   fclose(hFile);
   
   /* Check if input file is available */
   hFile = fopen(FileName, "rb");
   if (NULL == hFile)
   {
      printf("Error, input file \"%s\" not found\n", FileName);
      GOTO_END(-3);
   }
   fclose(hFile);
      
   /********************************************/
   /*  At this point all parameter was parsed  */
   /********************************************/
   
   printf("Public key: %s\n", KeyName);
   printf("Input file: %s\n", FileName);
   printf("\n");
   
   rc = VerifySignature();

end:
   
   return(rc);
} /* main */

/*** EOF ***/
