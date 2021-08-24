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
*  16.04.2021  mifi  First Version.
**************************************************************************/
#define __TNP_C__

/*=======================================================================*/
/*  Includes                                                             */
/*=======================================================================*/
#include <windows.h>
#include <stdio.h>
#include "stdint.h"
#include "tnp.h"

/*=======================================================================*/
/*  All Structures and Common Constants                                  */
/*=======================================================================*/

#define SERVER_NAME     "TinyES3"

#define MAX_IFACE_CNT   8
#define MAX_SERVER_CNT  8

#define GOTO_END(_a)    { rc = _a; goto end; }


/*
 * Added support for SIO_GET_INTERFACE_LIST
 */
#define SIO_GET_INTERFACE_LIST   _IOR ('t', 127, ULONG)

typedef struct in6_addr
{
   union 
   {
      UCHAR  Byte[16];
      USHORT Word[8];
   } u;
} IN6_ADDR, *PIN6_ADDR, *LPIN6_ADDR;

struct sockaddr_in6_old
{
   SHORT    sin6_family;
   USHORT   sin6_port;
   ULONG    sin6_flowinfo;
   IN6_ADDR sin6_addr;
};

typedef union sockaddr_gen 
{
   struct sockaddr         Address;
   struct sockaddr_in      AddressIn;
   struct sockaddr_in6_old AddressIn6;
} sockaddr_gen;

typedef struct _INTERFACE_INFO 
{
   ULONG        iiFlags;
   sockaddr_gen iiAddress;
   sockaddr_gen iiBroadcastAddress;
   sockaddr_gen iiNetmask;
} INTERFACE_INFO, *LPINTERFACE_INFO;

/*=======================================================================*/
/*  Definition of all local Data                                         */
/*=======================================================================*/

typedef struct _iface_
{
   SOCKET  Socket;
   DWORD  dAddress;
} IFACE;

static int        nWSAInitDone = 0;

static int        nIfaceCount;
static IFACE       IfaceList[MAX_IFACE_CNT];

static int        nServerCount;
static ES3_SERVER  ServerList[MAX_SERVER_CNT];

/*=======================================================================*/
/*  Definition of prototypes                                             */
/*=======================================================================*/

/*=======================================================================*/
/*  Definition of all local Procedures                                   */
/*=======================================================================*/

/*************************************************************************/
/*  GetInterfaceList                                                     */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: none                                                         */
/*************************************************************************/
static void GetInterfaceList (void)
{
   int                  rc;
   SOCKET               Socket;
   INTERFACE_INFO       InterfaceList[MAX_IFACE_CNT];
   struct sockaddr_in *pAddress;
   int                 nInterfacesCnt;
   DWORD               dBytesReturn;
   DWORD               dValue;
   int                 nIndex;
   int                 nOptionValue;

   /* Default, clear data */
   nIfaceCount = 0;
   memset(&IfaceList, 0x00, sizeof(IfaceList));

   /* Get interface list */
   Socket = socket(AF_INET, SOCK_DGRAM, 0);
   if (Socket != INVALID_SOCKET)
   {
      /* Try to get the Interface List info */
      rc = WSAIoctl(Socket, SIO_GET_INTERFACE_LIST, NULL, 0,
                    InterfaceList, sizeof(InterfaceList),
                    &dBytesReturn, NULL, NULL);
      if (0 == rc)
      {
         /* The socket is not needed anymore */
         closesocket(Socket);

         /* Get interface count */
         nInterfacesCnt = dBytesReturn / sizeof(INTERFACE_INFO);

         nIfaceCount = 0;
         for (nIndex = 0; nIndex < nInterfacesCnt; nIndex++)
         {
            /* Address*/
            pAddress = (struct sockaddr_in *)&(InterfaceList[nIndex].iiAddress);
            dValue = ntohl(pAddress->sin_addr.s_addr);

            /* Check for 127.0.0.1, this is not needed here */
            if ((dValue != 0x7F000001) && (nIfaceCount < MAX_IFACE_CNT))
            {
               /* Create interface socket */
               IfaceList[nIfaceCount].Socket = socket(AF_INET, SOCK_DGRAM, 0);
               if (INVALID_SOCKET == IfaceList[nIfaceCount].Socket)
               {
                  /* Fatal error */
                  exit(0);
               }

               /* Add socket option BROADCAST */
               nOptionValue = TRUE;
               setsockopt(IfaceList[nIfaceCount].Socket, SOL_SOCKET, SO_BROADCAST, (char *)&nOptionValue, sizeof(BOOL));

               /* Set socket option RCVTIMEO to 200ms*/
               nOptionValue = 200;
               setsockopt(IfaceList[nIfaceCount].Socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&nOptionValue, sizeof(BOOL));

               /* Save address info */
               IfaceList[nIfaceCount].dAddress = dValue;

               nIfaceCount++;
            }
         }
      }
   }

} /* GetInterfaceList */

/*=======================================================================*/
/*  All code exported                                                    */
/*=======================================================================*/

/*************************************************************************/
/*  tnp_Start                                                            */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: 0 = OK / error cause                                         */
/*************************************************************************/
int tnp_Start (void)
{
   int            rc = 0;
   WSADATA        WSAData;
   WORD          wVersion = WINSOCK_VERSION;
   int           nIndex;
   SOCKADDR_IN  saSource;

   /* 
    * Initialize Winsocket 
    */
   if (WSAStartup(wVersion, &WSAData) != 0)
   {
      printf("WSAStartup failed. Error: %d\r\n", WSAGetLastError());
      exit(-1);
   }
   nWSAInitDone = 1;

   /* 
    * Get interface list 
    */
   GetInterfaceList();
   if(0 == nIfaceCount) 
   {
      printf("Error, could not find any ethernet interfaces.\r\n");
      GOTO_END(-1);
   }
   
   /* 
    * Bind to interface 
    */
   for (nIndex = 0; nIndex < nIfaceCount; nIndex++)
   {
      /* Set address and port */
      saSource.sin_addr.s_addr = htonl(IfaceList[nIndex].dAddress);
      saSource.sin_port        = htons(TNP_UDP_PORT);
      saSource.sin_family      = AF_INET;

      /* bind socket */
      rc = bind(IfaceList[nIndex].Socket, (const struct sockaddr*)&saSource, sizeof(SOCKADDR_IN));
      if (rc != 0)
      {
         printf("Error, could not bind interfaces.\r\n");
         printf("Please close the \"Tiny Network Explorer\".\r\n");
         GOTO_END(-2);
      }
   }

   rc = 0;   

end:

   return(rc);
} /* main */

/*************************************************************************/
/*  tnp_Stop                                                             */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: none                                                         */
/*************************************************************************/
void tnp_Stop (void)
{
   if (1 == nWSAInitDone)
   {
      WSACleanup();
   }
   
} /* tnp_Stop */

/*************************************************************************/
/*  tnp_ES3Search                                                        */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: 0 = OK / error cause                                         */
/*************************************************************************/
int tnp_ES3Search (void)
{
   int            rc = 0;
   int           nIndex;
   int          nAddressLen;
   SOCKADDR_IN  saDest;
   SOCKADDR_IN  saSource;
   TNP_SETUP      Setup; 
   
   /* Default, clear data */
   nServerCount = 0;
   memset(&ServerList, 0x00, sizeof(ServerList));
   
   /*
    * Send request
    */                                  

   /* Fill the packet */ 
   memset(&Setup, 0x00, sizeof(TNP_SETUP));
   Setup.dMagic1  = TNP_HEADER_MAGIC_1;
   Setup.dMagic2  = TNP_HEADER_MAGIC_2;
   Setup.wSize    = sizeof(TNP_SETUP);
   Setup.wVersion = TNP_HEADER_VERSION;
   Setup.bMode    = TNP_SETUP_REQUEST;

   /* Send to all interfaces */
   for (nIndex = 0; nIndex < nIfaceCount; nIndex++)
   {
      /* Set address and port */
      saDest.sin_addr.s_addr = INADDR_BROADCAST;
      saDest.sin_port        = htons(TNP_UDP_PORT);
      saDest.sin_family      = AF_INET;
   
      /* Send the packet */
      sendto(IfaceList[nIndex].Socket, (const char *)&Setup, sizeof(TNP_SETUP), 0, 
             (const struct sockaddr*)&saDest, sizeof(SOCKADDR_IN));
   }

   /*
    * Wait for response
    */

   /* Check all interfaces */
   for (nIndex = 0; nIndex < nIfaceCount; nIndex++)
   {
      while (1)
      {
         nAddressLen = sizeof(SOCKADDR_IN);
         rc = recvfrom(IfaceList[nIndex].Socket, 
                       (char *)&Setup, 
                       sizeof(TNP_SETUP), 
                       0,
                       (struct sockaddr*)&saSource,
                       &nAddressLen);

         if( (rc             != SOCKET_ERROR)       &&
             (Setup.dMagic1  == TNP_HEADER_MAGIC_1) &&
             (Setup.dMagic2  == TNP_HEADER_MAGIC_2) &&
             (Setup.wSize    == sizeof(TNP_SETUP))  &&
             (Setup.wVersion == TNP_HEADER_VERSION) )
         {
            /* Check if MAC addres is != 0 */
            if ((0 == Setup.bMACAddress[0]) && 
                (0 == Setup.bMACAddress[1]) && 
                (0 == Setup.bMACAddress[2]) && 
                (0 == Setup.bMACAddress[3]) && 
                (0 == Setup.bMACAddress[4]) && 
                (0 == Setup.bMACAddress[5]) )
            {
               /* Do nothing, this was the request we have send */
            }
            else
            {
               /* Check for response */
               if( (Setup.bMode == TNP_SETUP_RESPONSE)    ||
                   (Setup.bMode == TNP_SETUP_RESPONSE_ES) )
               {  
                  /* Check if this is a "TinyES3" server */
                  if ((0 == strcmp(Setup.Name, SERVER_NAME)) && (nServerCount < MAX_SERVER_CNT))
                  {
                     /* Copy server data */
                     memcpy(ServerList[nServerCount].bMACAddress, Setup.bMACAddress, 6);
                     ServerList[nServerCount].dAddress   = Setup.dAddress;
                     ServerList[nServerCount].dFWVersion = Setup.dFWVersion;
                     memcpy(ServerList[nServerCount].Name, Setup.Name, TNP_MAX_NAME_LEN);
                     memcpy(ServerList[nServerCount].Location, Setup.Location, TNP_MAX_LOCATION_LEN);
                     
                     nServerCount++;
                  }                            
               }            
            }   
         }
         else
         {
            /* No more data from this interface */
            break;
         }
      }
   }
   
   if (0 == nServerCount)
   {
      /* Error, no server found */
      rc = -1;
   }
   else
   {
      /* No error */
      rc = 0;
   }

   return(rc);
} /* tnp_ES3Search */

/*************************************************************************/
/*  tnp_ES3GetServerCount                                                */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: nServerCount                                                 */
/*************************************************************************/
int tnp_ES3GetServerCount (void)
{
   return(nServerCount);
} /* tnp_ES3GetServerCount */

/*************************************************************************/
/*  tnp_ES3GetServer                                                     */
/*                                                                       */
/*  In    : nIndex, pServer                                              */
/*  Out   : pServer                                                      */
/*  Return: 0 = OK / error cause                                         */
/*************************************************************************/
int tnp_ES3GetServer (int nIndex, ES3_SERVER *pServer)
{
   int rc = -1;

   /* Check for valid parameters */   
   if ((nIndex >= 0) && (nIndex < nServerCount) && (pServer != NULL))
   {
      memcpy(pServer, &ServerList[nIndex], sizeof(ES3_SERVER));
      rc = 0;
   }
   
   return(rc);
} /* tnp_ES3GetServer */

/*** EOF ***/
