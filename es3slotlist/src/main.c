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
*  14.08.2021  mifi  First Version, release version v1.00.
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
#include "tnp.h"
#include "es3_rpc.h"

#include "mbedtls/platform.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

/*=======================================================================*/
/*  All Structures and Common Constants                                  */
/*=======================================================================*/

#define VERSION         "1.20"

#define GOTO_END(_a)    { rc = _a; goto end; }

#define SLOT_NAME_SIZE  (19)
#define FILE_NAME_SIZE  (_MAX_PATH-1)
#define IP_NAME_SIZE    (15)

/*=======================================================================*/
/*  Definition of all local Data                                         */
/*=======================================================================*/

static char IPName[IP_NAME_SIZE+1];

static char UserName[_MAX_PATH];
static char ComputerName[_MAX_PATH];
static char HomePath[_MAX_PATH];
static char ES3Folder[_MAX_PATH];
static char PrivFilename[_MAX_PATH];
static char PubFilename[_MAX_PATH];

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
   printf("es3slotlist v%s compiled "__DATE__" "__TIME__"\n", VERSION);
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
  printf("Usage: es3slotlist [-ip a.b.c.d] [-v] [-d]\n");
  printf("\n");
  printf("  -ip  Select IP-Address of the signing server,\n");
  printf("       e.g. -ip 192.168.1.200\n");
  printf("  -v   Show version information only\n");
  printf("  -d   Discover, search server only\n");
  
} /* OutputUsage */

/*************************************************************************/
/*  Discover                                                             */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: 0 = OK / error cause                                         */
/*************************************************************************/
static int Discover (void)
{
   int              rc = 0;
   int             nIndex;
   int             nServerCount;
   ES3_SERVER       Server;
   char             String[64];
   struct in_addr iaAddr;   
   
   /*
    * Search ES3 server
    */
   printf("Searching Embedded Secure Signing Server...\n\n"); 
   rc = tnp_ES3Search(); 
   if (rc != 0)
   {
      printf("No server found.\n");
   }
   else
   {
      nServerCount = tnp_ES3GetServerCount();

	   printf("MAC-Address        IP-Address       Server - Version  Location\n");
	   printf("======================================================================\n");
      
      for (nIndex = 0; nIndex < nServerCount; nIndex++)
      {
         rc = tnp_ES3GetServer(nIndex, &Server);
         if (0 == rc)
         {
            _snprintf(String, sizeof(String), "%02X:%02X:%02X:%02X:%02X:%02X",
               Server.bMACAddress[0], Server.bMACAddress[1], Server.bMACAddress[2],
               Server.bMACAddress[3], Server.bMACAddress[4], Server.bMACAddress[5]);
            printf("%s  ", String);
         
            iaAddr.s_addr = Server.dAddress;
            printf("%-15s  ", inet_ntoa(iaAddr));

            _snprintf(String, sizeof(String), "%s - v%d.%02d", Server.Name, Server.dFWVersion/100, Server.dFWVersion%100);
            printf("%s   %s\r\n", String, Server.Location);
         }
      }
   }

   return(rc);
} /* Discover */

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

/*************************************************************************/
/*  OutputSlotList                                                       */
/*                                                                       */
/*  In    : pRxMsg                                                       */
/*  Out   : none                                                         */
/*  Return: none                                                         */
/*************************************************************************/
static void OutputSlotList (es3_msg_t *pRxMsg)
{
   int nSlot;
   
   printf("\r\n");
   printf("Available slots:\r\n");
   printf("\r\n");
   
   for (nSlot = 0; nSlot < ES3_SLOT_COUNT; nSlot++)
   {
      if (pRxMsg->Data.rGetList.SlotArray[nSlot][0] != 0)
      {
         printf(" %s\r\n", pRxMsg->Data.rGetList.SlotArray[nSlot]);
      }   
   }

} /* OutputSlotList */

/*************************************************************************/
/*  HandleGetListReq                                                     */
/*                                                                       */
/*  In    : pTxMsg, pRxMsg, dAddress                                     */ 
/*  Out   : pRxMsg                                                       */
/*  Return: 0 = OK / error cause                                         */
/*************************************************************************/
static int HandleGetListReq (es3_msg_t *pTxMsg, es3_msg_t *pRxMsg, DWORD dAddress)
{
   int            rc = -1;
   int           nAddressLen;
   int           nOptionValue;
   SOCKET         Socket;
   SOCKADDR_IN  saDest;
   SOCKADDR_IN  saSource;

   /* Get socket */
   Socket = socket(AF_INET, SOCK_DGRAM, 0);
   if (Socket != INVALID_SOCKET)
   {
      /* Set socket option RCVTIMEO to 1000ms*/
      nOptionValue = 1000;
      setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&nOptionValue, sizeof(BOOL));

      /* Set address and port */
      saDest.sin_addr.s_addr = dAddress;
      saDest.sin_port        = htons(ES3_SERVER_PORT);
      saDest.sin_family      = AF_INET;
   
      /* Send the request to the server */
      sendto(Socket, (const char *)pTxMsg, ES3_RPC_HEADER_SIZE + pTxMsg->Header.Len, 0, 
             (const struct sockaddr*)&saDest, sizeof(SOCKADDR_IN));

      /* Wait for the response from the server */          
      nAddressLen = sizeof(SOCKADDR_IN);
      rc = recvfrom(Socket, (char *)pRxMsg, sizeof(es3_msg_t), 
                    0, (struct sockaddr*)&saSource, &nAddressLen);
                    
      /* Socket can be closed */
      closesocket(Socket);

      /* Check size of the return data */                 
      if (rc != -1)
      {
         rc = (rc >= ES3_RPC_HEADER_SIZE) ? 0 : -1;
      }   
   }      
   
   return(rc);
} /* HandleGetListReq */

/*************************************************************************/
/*  SlotList                                                             */
/*                                                                       */
/*  In    : dAddress                                                     */ 
/*  Out   : none                                                         */
/*  Return: 0 = OK / error cause                                         */
/*************************************************************************/
static int SlotList (DWORD dAddress)
{
   int                      rc;
   mbedtls_pk_context       pk;
   mbedtls_entropy_context  entropy;
   mbedtls_ctr_drbg_context ctr_drbg;
   size_t                   len;
   size_t                   SigLen;
   uint8_t                  Hash[32];
   es3_msg_t                TxMsg;
   es3_msg_t                RxMsg;
   
   /*
    * Prepare key generation
    */
   mbedtls_pk_init(&pk);
   mbedtls_ctr_drbg_init(&ctr_drbg);
   mbedtls_entropy_init(&entropy);
   
//   psa_crypto_init();
      
   /*
    * Create GetList request
    */
   memset(&TxMsg, 0x00, sizeof(es3_msg_t));
   
   TxMsg.Header.Magic1  = ES3_RPC_HEADER_MAGIC_1;
   TxMsg.Header.Magic2  = ES3_RPC_HEADER_MAGIC_2;
   TxMsg.Header.SizeVer = ES3_RPC_SIZEVER;
   TxMsg.Header.Func    = ES3_MSG_GET_LIST;   
   _snprintf(TxMsg.Header.User, ES3_RPC_USER_SIZE-1, "%s@%s", UserName, ComputerName);
   
   TxMsg.Header.Len     = ES3_CALL_GET_LIST_SIZE; 
   _snprintf(TxMsg.Data.cGetList.Slot, ES3_RPC_SLOT_SIZE-1, "root-of-trust");


   /*
    * Sign the GetList request
    */   
    
   /* Hash GetList */    
   len = ES3_CALL_GET_LIST_SIZE;
   rc = mbedtls_sha256_ret((uint8_t*)&TxMsg.Data, len, Hash, 0);
   if (rc != 0) GOTO_END(-4); 

   /* Seed the random generator */
   rc =  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) "TinyES3sign", 11);
   if (rc != 0) GOTO_END(-5); 

   /* Read private key */   
   rc = mbedtls_pk_parse_keyfile(&pk, PrivFilename, NULL);
   if (rc != 0) GOTO_END(-6);
   
   /* Create signature */   
   SigLen = ES3_RPC_SIG_SIZE;
   rc = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, Hash, 0, 
                        TxMsg.Header.Sig, &SigLen,
                        mbedtls_ctr_drbg_random, &ctr_drbg);
   if (rc != 0) GOTO_END(-7);
   
   /* Check signature size */
   if (SigLen > ES3_RPC_SIG_SIZE) GOTO_END(-8);
   
   TxMsg.Header.SigLen = (uint8_t)SigLen;

   rc = HandleGetListReq(&TxMsg, &RxMsg, dAddress); 
   if (0 == rc)
   {
      rc = RxMsg.Header.Result;
      switch (rc)
      {
         case ES3_RPC_OK:         printf("\nSlot list successfully received.\n");                         break;
         case ES3_RPC_ERROR:      printf("\nAn internal error has occurred: %d\n", rc);                   break;
         case ES3_RPC_ERR_LOCKED: printf("\nError, the encrypted keystore is currently still locked.\n"); break;
         case ES3_RPC_ERR_USER:   printf("\nError, user \"%s\" not available.\n", TxMsg.Header.User);     break;
         
         case ES3_RPC_ERR_ECC:
         case ES3_RPC_ERR_LEN:
         case ES3_RPC_ERR_FUNC:
         default:
         {
            printf("\nAn internal error has occurred: %d\n", rc);
            break;
         }
      }
      
      /* In case of no error, create output file */
      if (0 == rc)
      {
         OutputSlotList(&RxMsg);
      }
      
   }
   else
   {
      printf("\nError, no response from server.\n");   
   }

end:

   mbedtls_pk_free(&pk);
   mbedtls_ctr_drbg_free(&ctr_drbg);
   mbedtls_entropy_free(&entropy);

   return(rc);   
} /* GetPub */

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
   int              rc = 0;
   int              Index;
   int              CmdUnknown  = 0;
   int              CmdVersion  = 0;
   int              CmdDiscover = 0;
   int              CmdIP       = 0;
   DWORD           dAddress     = 0;
   struct in_addr iaAddr;   
   ES3_SERVER       Server;
   char             String[64];
   
   
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
         /* Check ip address */
         if (0 == strcmp(argv[Index], "-ip"))
         {
            if ((Index + 1) < argc)
            {
               CmdIP = 1;   
               Index++;
               _snprintf(IPName, IP_NAME_SIZE, "%s", argv[Index]);
            }               
         }
         /* Check version information only */
         else if (0 == strcmp(argv[Index], "-v"))
         {
            CmdVersion = 1;
         }
         /* Check for discover */
         else if (0 == strcmp(argv[Index], "-d"))
         {
            CmdDiscover = 1;
         }
         else
         {
            /* Ups, unknown command */
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
    * Start the TNP protocol
    */
   rc = tnp_Start();
   if (rc != 0) GOTO_END(rc);
   
   /*
    * Check for discover command only
    */
   if (1 == CmdDiscover)
   {
      Discover();
      GOTO_END(0);
   }    
   
   /********************************************/
   /*  At this point all parameter was parsed  */
   /********************************************/
   
   /* 
    * Retrieve infos like user, computer name and home path
    */    
   rc = GetEnvironemnt();
   if (rc != 0)
   {
      printf("Error, could not retrieve environment variables.\n");
      GOTO_END(-3);
   }
   
   /* 
    * Check if a server should be selected automatically 
    */ 
   if (0 == CmdIP)
   {
      /* Search server */ 
      printf("Searching Embedded Secure Signing Server...\n\n"); 
      rc = tnp_ES3Search(); 
      if (rc != 0)
      {
         printf("No server found.\n");
         GOTO_END(-4);
      }
   }
   else
   {
      /* Use the given IP-Address */
      dAddress = inet_addr(IPName);
      if (INADDR_NONE == dAddress)
      {
         printf("Error, IP-Address invalid: %s\n", IPName);
         GOTO_END(-5);
      }
   }      

   printf("SlotList parameters\n");
   printf("====================\n");
    
   if (1 == CmdIP)
   { 
      /* Use the given IP-Address */
      iaAddr.s_addr = dAddress;
      printf("Server: %s\n", inet_ntoa(iaAddr));
   }
   else
   {
      /* Use the first server which was found in the network */
      rc = tnp_ES3GetServer(0, &Server);
      if (0 != rc) GOTO_END(-6);
      
      dAddress = Server.dAddress;
      iaAddr.s_addr = dAddress;
      printf("Server: %s  ", inet_ntoa(iaAddr));

      /* Output additional server informations */
      _snprintf(String, sizeof(String), "%02X:%02X:%02X:%02X:%02X:%02X",
         Server.bMACAddress[0], Server.bMACAddress[1], Server.bMACAddress[2],
         Server.bMACAddress[3], Server.bMACAddress[4], Server.bMACAddress[5]);
      printf("%s  ", String);
      
      _snprintf(String, sizeof(String), "%s - v%d.%02d", Server.Name, Server.dFWVersion/100, Server.dFWVersion%100);
      printf("%s  %s\r\n", String, Server.Location);
   }   

   /************************************************/
   /*  At this point all parameters are available  */
   /************************************************/
   
   rc = SlotList(dAddress);

end:
   
   tnp_Stop();   

   return(rc);
} /* main */

/*** EOF ***/
