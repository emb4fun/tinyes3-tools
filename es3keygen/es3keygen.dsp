# Microsoft Developer Studio Project File - Name="es3keygen" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=es3keygen - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "es3keygen.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "es3keygen.mak" CFG="es3keygen - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "es3keygen - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "es3keygen - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "es3keygen - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I ".\inc" /I "..\library\mbedtls\include" /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D _WIN32_WINNT=0x0400 /YX /FD /c
# ADD BASE RSC /l 0x407 /d "NDEBUG"
# ADD RSC /l 0x407 /d "NDEBUG"
# SUBTRACT RSC /x
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386

!ELSEIF  "$(CFG)" == "es3keygen - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I ".\inc" /I "..\library\mbedtls\include" /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D _WIN32_WINNT=0x0400 /YX /FD /GZ /c
# ADD BASE RSC /l 0x407 /d "_DEBUG"
# ADD RSC /l 0x407 /d "_DEBUG"
# SUBTRACT RSC /x
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept

!ENDIF 

# Begin Target

# Name "es3keygen - Win32 Release"
# Name "es3keygen - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Group "library"

# PROP Default_Filter ""
# Begin Group "mbedtls"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\library\mbedtls\library\aes.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\asn1parse.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\asn1write.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\base64.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\bignum.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\ccm.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\cipher.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\cipher_wrap.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\ctr_drbg.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\ecdsa.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\ecp.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\ecp_curves.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\entropy.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\entropy_poll.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\hmac_drbg.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\md.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\md5.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\md_wrap.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\oid.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\pem.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\pk.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\pk_wrap.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\pkcs12.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\pkcs5.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\pkparse.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\pkwrite.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\platform.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\platform_util.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\sha256.c
# End Source File
# Begin Source File

SOURCE=..\library\mbedtls\library\timing.c
# End Source File
# End Group
# End Group
# Begin Source File

SOURCE=.\src\main.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# End Target
# End Project
