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
*  17.04.2021  mifi  Release version v1.00.
**************************************************************************/
#define __MAIN_C__

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

#define VERSION         "1.10"

#define GOTO_END(_a)    { rc = _a; goto end; }

/*=======================================================================*/
/*  Definition of all local Data                                         */
/*=======================================================================*/

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
   printf("es3discover v%s compiled "__DATE__" "__TIME__"\n", VERSION);
   printf("(c) 2021 by Michael Fischer (www.emb4fun.de)\n");
   printf("\n");
   
} /* OutputStartMessage */

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
   int             nIndex;
   int             nServerCount;
   ES3_SERVER       Server;
   char             String[64];
   struct in_addr iaAddr;   
   
   (void)argc;
   (void)argv;

   /*
    * Output start message
    */
   OutputStartMessage();

   /*
    * Start the TNP protocol
    */
   rc = tnp_Start();
   if (rc != 0) GOTO_END(rc);
   
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


end:
   
   tnp_Stop();   

   return(rc);
} /* main */

/*** EOF ***/
