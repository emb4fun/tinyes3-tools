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
*  16.04.2021  mifi  First Version.
 *  21.11.2026  mifi  Ported to MSYS2-UCRT64 (MinGW) and Linux.
**************************************************************************/
#define __TNP_C__

/*=======================================================================*/
/*  Includes                                                             */
/*=======================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "net_compat.h"
#include "tnp.h"

/*=======================================================================*/
/*  All Structures and Common Constants                                  */
/*=======================================================================*/

#define SERVER_NAME     "TinyES3"

#define MAX_IFACE_CNT   8
#define MAX_SERVER_CNT  8

#define GOTO_END(_a)    { rc = _a; goto end; }

/*=======================================================================*/
/*  Definition of all local Data                                         */
/*=======================================================================*/

typedef struct _iface_
{
   net_socket_t Socket;      /* Windows: socket per interface */
   uint32_t     dAddress;    /* Interface address (host byte order) */
   uint32_t     dMask;       /* Interface netmask (host byte order), Linux only */
} IFACE;

static int        nNetInitDone = 0;

#if !defined(_WIN32)
/* Linux: Single socket bound to INADDR_ANY, used to send and receive.
 * Binding to the specific interface address does not work in every
 * environment (e.g. WSL2 mirrored networking does not deliver packets
 * to sockets bound to a specific IP address). */
static net_socket_t AnySocket = NET_INVALID_SOCKET;
#endif

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
/*  AddInterface                                                         */
/*                                                                       */
/*  In    : dAddress                                                     */
/*  Out   : none                                                         */
/*  Return: none                                                         */
/*************************************************************************/
static void AddInterface (uint32_t dAddress, uint32_t dMask)
{
   if (nIfaceCount >= MAX_IFACE_CNT)
   {
      /* No more space in the interface list */
      return;
   }

#if defined(_WIN32)
   {
      net_socket_t Socket;
      int          nOptionValue;

      /* Create interface socket */
      Socket = socket(AF_INET, SOCK_DGRAM, 0);
      if (Socket == NET_INVALID_SOCKET)
      {
         /* Fatal error */
         exit(0);
      }

      /* Add socket option BROADCAST */
      nOptionValue = 1;
      (void)setsockopt(Socket, SOL_SOCKET, SO_BROADCAST,
                       (const char *)&nOptionValue, sizeof(nOptionValue));

      /* Set socket option RCVTIMEO to 200ms */
      (void)net_set_recv_timeout(Socket, 200);

      /* Save socket info */
      IfaceList[nIfaceCount].Socket = Socket;
   }
#endif

   /* Save address info */
   IfaceList[nIfaceCount].dAddress = dAddress;
   IfaceList[nIfaceCount].dMask    = dMask;

   nIfaceCount++;

} /* AddInterface */

/*************************************************************************/
/*  GetInterfaceList                                                     */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: none                                                         */
/*************************************************************************/
static void GetInterfaceList (void)
{
   uint32_t           dValue;
   struct sockaddr_in *pAddress;
#if defined(_WIN32)
   SOCKET             Socket;
   INTERFACE_INFO     InterfaceList[MAX_IFACE_CNT];
   DWORD              dBytesReturn;
   int                nInterfacesCnt;
   int                nIndex;
#else
   struct ifaddrs    *pIfAddrs = NULL;
   struct ifaddrs    *pIf;
   struct sockaddr_in *pNetmask;
   uint32_t          dMask;
#endif

   /* Default, clear data */
   nIfaceCount = 0;
   memset(&IfaceList, 0x00, sizeof(IfaceList));

#if defined(_WIN32)

   /* Get interface list */
   Socket = socket(AF_INET, SOCK_DGRAM, 0);
   if (Socket != INVALID_SOCKET)
   {
      /* Try to get the Interface List info */
      if (WSAIoctl(Socket, SIO_GET_INTERFACE_LIST, NULL, 0,
                   InterfaceList, sizeof(InterfaceList),
                   &dBytesReturn, NULL, NULL) == 0)
      {
         /* The socket is not needed anymore */
         closesocket(Socket);

         /* Get interface count */
         nInterfacesCnt = dBytesReturn / sizeof(INTERFACE_INFO);

         for (nIndex = 0; nIndex < nInterfacesCnt; nIndex++)
         {
            /* Address */
            pAddress = (struct sockaddr_in *)&(InterfaceList[nIndex].iiAddress);
            dValue   = ntohl(pAddress->sin_addr.s_addr);

            /* Check for 127.0.0.1, this is not needed here */
            if (dValue != 0x7F000001)
            {
               AddInterface(dValue, 0);
            }
         }
      }
      else
      {
         /* The socket is not needed anymore */
         closesocket(Socket);
      }
   }

#else

   /* Get interface list */
   if (getifaddrs(&pIfAddrs) == 0)
   {
      for (pIf = pIfAddrs; pIf != NULL; pIf = pIf->ifa_next)
      {
         if ((pIf->ifa_addr != NULL) && (pIf->ifa_addr->sa_family == AF_INET))
         {
            /* Address */
            pAddress = (struct sockaddr_in *)pIf->ifa_addr;
            dValue   = ntohl(pAddress->sin_addr.s_addr);

            /* Check for 127.0.0.1, this is not needed here */
            if (dValue != 0x7F000001)
            {
               /* Netmask, used for the directed broadcast address */
               pNetmask = (struct sockaddr_in *)pIf->ifa_netmask;
               dMask    = (pNetmask != NULL) ? ntohl(pNetmask->sin_addr.s_addr) : 0;

               AddInterface(dValue, dMask);
            }
         }
      }
      freeifaddrs(pIfAddrs);
   }

#endif

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
#if defined(_WIN32)
   int            nIndex;
#endif
   struct sockaddr_in saSource;

   /*
    * Initialize the socket subsystem
    */
   if (net_socket_startup() != 0)
   {
      printf("Socket startup failed.\r\n");
      exit(-1);
   }
   nNetInitDone = 1;

   /*
    * Get interface list
    */
   GetInterfaceList();
   if(0 == nIfaceCount)
   {
      printf("Error, could not find any ethernet interfaces.\r\n");
      GOTO_END(-1);
   }

#if defined(_WIN32)

   /*
    * Windows: Bind one socket to each interface
    */
   for (nIndex = 0; nIndex < nIfaceCount; nIndex++)
   {
      /* Set address and port */
      saSource.sin_addr.s_addr = htonl(IfaceList[nIndex].dAddress);
      saSource.sin_port        = htons(TNP_UDP_PORT);
      saSource.sin_family      = AF_INET;

      /* bind socket */
      rc = bind(IfaceList[nIndex].Socket, (const struct sockaddr*)&saSource, sizeof(struct sockaddr_in));
      if (rc != 0)
      {
         printf("Error, could not bind interfaces.\r\n");
         printf("Please close the \"Tiny Network Explorer\".\r\n");
         GOTO_END(-2);
      }
   }

#else

   /*
    * Linux: Use one single socket bound to INADDR_ANY. Binding to
    * a specific interface address does not work in every environment
    * (e.g. WSL2 in mirrored networking mode does not deliver packets
    * to sockets which are bound to a specific IP address).
    */
   {
      int nOptionValue;

      AnySocket = socket(AF_INET, SOCK_DGRAM, 0);
      if (AnySocket == NET_INVALID_SOCKET)
      {
         printf("Error, could not create socket.\r\n");
         GOTO_END(-2);
      }

      /* Add socket option BROADCAST */
      nOptionValue = 1;
      (void)setsockopt(AnySocket, SOL_SOCKET, SO_BROADCAST,
                       (const char *)&nOptionValue, sizeof(nOptionValue));

      /* Set socket option RCVTIMEO to 200ms */
      (void)net_set_recv_timeout(AnySocket, 200);

      /* Bind the socket to INADDR_ANY */
      saSource.sin_addr.s_addr = htonl(INADDR_ANY);
      saSource.sin_port        = htons(TNP_UDP_PORT);
      saSource.sin_family      = AF_INET;

      rc = bind(AnySocket, (const struct sockaddr*)&saSource, sizeof(struct sockaddr_in));
      if (rc != 0)
      {
         printf("Error, could not bind socket.\r\n");
         GOTO_END(-2);
      }
   }

#endif

   rc = 0;

end:

   return(rc);
} /* tnp_Start */

/*************************************************************************/
/*  tnp_Stop                                                             */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: none                                                         */
/*************************************************************************/
void tnp_Stop (void)
{
   if (1 == nNetInitDone)
   {
#if !defined(_WIN32)
      if (AnySocket != NET_INVALID_SOCKET)
      {
         net_close_socket(AnySocket);
         AnySocket = NET_INVALID_SOCKET;
      }
#endif
      net_socket_cleanup();
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
   int           nDupIndex;
   net_socklen_t nAddressLen;
   struct sockaddr_in saDest;
   struct sockaddr_in saSource;
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

#if defined(_WIN32)

   /* Send the limited broadcast on all interfaces */
   for (nIndex = 0; nIndex < nIfaceCount; nIndex++)
   {
      /* Set address and port */
      saDest.sin_addr.s_addr = INADDR_BROADCAST;
      saDest.sin_port        = htons(TNP_UDP_PORT);
      saDest.sin_family      = AF_INET;
   
      /* Send the packet */
      sendto(IfaceList[nIndex].Socket, (const char *)&Setup, sizeof(TNP_SETUP), 0, 
             (const struct sockaddr*)&saDest, sizeof(struct sockaddr_in));
   }

#else

   /*
    * Linux: Send the limited broadcast and in addition a directed
    * broadcast (address | ~netmask) on every interface, because the
    * limited broadcast is only routed via the default interface when
    * the socket is bound to INADDR_ANY.
    */
   saDest.sin_addr.s_addr = INADDR_BROADCAST;
   saDest.sin_port        = htons(TNP_UDP_PORT);
   saDest.sin_family      = AF_INET;
   (void)sendto(AnySocket, (const char *)&Setup, sizeof(TNP_SETUP), 0,
                (const struct sockaddr*)&saDest, sizeof(struct sockaddr_in));

   for (nIndex = 0; nIndex < nIfaceCount; nIndex++)
   {
      saDest.sin_addr.s_addr = htonl(IfaceList[nIndex].dAddress |
                                     ~IfaceList[nIndex].dMask);
      (void)sendto(AnySocket, (const char *)&Setup, sizeof(TNP_SETUP), 0,
                   (const struct sockaddr*)&saDest, sizeof(struct sockaddr_in));
   }

#endif

   /*
    * Wait for response
    */

   /*
    * Windows: Check all interface sockets
    * Linux:   Check the single socket
    */
#if defined(_WIN32)
   for (nIndex = 0; nIndex < nIfaceCount; nIndex++)
#endif
   {
      while (1)
      {
         nAddressLen = sizeof(struct sockaddr_in);
#if defined(_WIN32)
         rc = recvfrom(IfaceList[nIndex].Socket, 
                       (char *)&Setup, 
                       sizeof(TNP_SETUP), 
                       0,
                       (struct sockaddr*)&saSource,
                       &nAddressLen);
#else
         rc = recvfrom(AnySocket,
                       (char *)&Setup,
                       sizeof(TNP_SETUP),
                       0,
                       (struct sockaddr*)&saSource,
                       &nAddressLen);
#endif

         if( (rc             != NET_SOCKET_ERROR)   &&
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
                  if (0 == strcmp(Setup.Name, SERVER_NAME))
                  {
                     /* Check if this server is already in the list (e.g. if
                      * the request was sent as limited and directed broadcast) */
                     for (nDupIndex = 0; nDupIndex < nServerCount; nDupIndex++)
                     {
                        if (0 == memcmp(ServerList[nDupIndex].bMACAddress, Setup.bMACAddress, 6))
                        {
                           break;
                        }
                     }

                     /* Not a duplicate, copy server data */
                     if ((nDupIndex == nServerCount) && (nServerCount < MAX_SERVER_CNT))
                     {
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
