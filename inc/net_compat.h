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
*  21.11.2026  mifi  First Version, socket compatibility layer
*                    for Windows (Winsock) and Linux (BSD sockets).
**************************************************************************/
#if !defined(__NET_COMPAT_H__)
#define __NET_COMPAT_H__

/**************************************************************************
*  Includes
**************************************************************************/
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <unistd.h>
#endif

/**************************************************************************
*  Global Definitions
**************************************************************************/
#if defined(_WIN32)

typedef SOCKET    net_socket_t;   /* Socket handle */

typedef int       net_socklen_t;  /* Address length */

#define NET_INVALID_SOCKET   INVALID_SOCKET
#define NET_SOCKET_ERROR     SOCKET_ERROR

#else

typedef int       net_socket_t;   /* Socket handle (file descriptor) */

typedef socklen_t net_socklen_t;  /* Address length */

#define NET_INVALID_SOCKET   (-1)
#define NET_SOCKET_ERROR     (-1)

#endif

/**************************************************************************
*  Functions Definitions
**************************************************************************/

/*************************************************************************/
/*  net_socket_startup                                                   */
/*                                                                       */
/*  Initialize the socket subsystem (Winsock), no-op on Linux.           */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = error                                          */
/*************************************************************************/
#if defined(_WIN32)
static inline int net_socket_startup (void)
{
   WSADATA WSAData;

   if (WSAStartup(MAKEWORD(2, 2), &WSAData) != 0)
   {
      return -1;
   }
   return 0;

} /* net_socket_startup */
#else
static inline int net_socket_startup (void)
{
   return 0;

} /* net_socket_startup */
#endif

/*************************************************************************/
/*  net_socket_cleanup                                                   */
/*                                                                       */
/*  Clean up the socket subsystem (Winsock), no-op on Linux.            */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: none                                                         */
/*************************************************************************/
#if defined(_WIN32)
static inline void net_socket_cleanup (void)
{
   WSACleanup();

} /* net_socket_cleanup */
#else
static inline void net_socket_cleanup (void)
{
} /* net_socket_cleanup */
#endif

/*************************************************************************/
/*  net_close_socket                                                     */
/*                                                                       */
/*  Close a socket.                                                      */
/*                                                                       */
/*  In    : Socket                                                       */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = error                                          */
/*************************************************************************/
static inline int net_close_socket (net_socket_t Socket)
{
#if defined(_WIN32)
   return closesocket(Socket);
#else
   return close(Socket);
#endif

} /* net_close_socket */

/*************************************************************************/
/*  net_set_recv_timeout                                                 */
/*                                                                       */
/*  Set the receive timeout in milliseconds.                             */
/*                                                                       */
/*  In    : Socket, nTimeOutMs                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = error                                          */
/*************************************************************************/
static inline int net_set_recv_timeout (net_socket_t Socket, int nTimeOutMs)
{
#if defined(_WIN32)
   DWORD dTimeOut = (DWORD)nTimeOutMs;

   return setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO,
                     (const char *)&dTimeOut, sizeof(dTimeOut));
#else
   struct timeval TimeOut;

   TimeOut.tv_sec  = nTimeOutMs / 1000;
   TimeOut.tv_usec = (nTimeOutMs % 1000) * 1000;

   return setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO,
                     (const char *)&TimeOut, sizeof(TimeOut));
#endif

} /* net_set_recv_timeout */

#endif /* !__NET_COMPAT_H__ */

/*** EOF ***/