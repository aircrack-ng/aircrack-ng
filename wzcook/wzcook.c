/*
 *  Windows XP WEP key recovery program
 *
 *  Copyright (C) 2004,2005  Christophe Devine
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <windows.h>
#include <stdio.h>

#include "console.h" 

int prompt_exit( int retval )
{
    int i;
    printf( "\n  Keys have been stored in C:\\wepkeys.txt. Press Ctrl-C.\n" );
    scanf( "%d", &i );
    exit( retval );
}

int zero_key[32] =
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

int xor_key[32] =
{
    0x56, 0x66, 0x09, 0x42, 0x08, 0x03, 0x98, 0x01,
    0x4D, 0x67, 0x08, 0x66, 0x11, 0x56, 0x66, 0x09,
    0x42, 0x08, 0x03, 0x98, 0x01, 0x4D, 0x67, 0x08,
    0x66, 0x11, 0x56, 0x66, 0x09, 0x42, 0x08, 0x03
};

#define WZCSVC_LIST "Software\\Microsoft\\WZCSVC\\Parameters\\Interfaces"

char ServiceName[] = "WZCOOK";
char DisplayName[] = "WEP/WPA-PMK key recovery service";

typedef struct
{
  DWORD cbData;
  BYTE* pbData;
}
DATA_BLOB;

typedef BOOL (WINAPI *PROC1)
    (DATA_BLOB *,void *,void *,void *,
     void *,void *,DATA_BLOB *);

char * filename = "c:\\wepkeys.txt";

void WINAPI myHandler( DWORD fdwControl )
{
    if( fdwControl == SERVICE_CONTROL_SHUTDOWN )
    {
        ExitProcess( 0 );
    }
}

void WINAPI ServiceMain( DWORD dwArgc, LPTSTR *lpszArgv )
{
    FILE *f_out;
    char buffer[1024];
    char keystr[1024];

    int length, keytype, i;
    int keyidx1, keyidx2;

    HMODULE hCrypt32dll;
    PROC1 CryptUnprotectData;

    HKEY regkey_iface;
    HKEY regkey_wzcsvc;
    DATA_BLOB pIn, pOut;

    SERVICE_STATUS_HANDLE sth;
    SERVICE_STATUS status;

    sth = RegisterServiceCtrlHandler( ServiceName, myHandler );

    memset( &status, 0, sizeof( SERVICE_STATUS ) );

    status.dwServiceType        = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState       = SERVICE_RUNNING;
    status.dwControlsAccepted   = SERVICE_ACCEPT_SHUTDOWN;
    status.dwWin32ExitCode      = NO_ERROR;

    SetServiceStatus( sth, &status );

    if( ( f_out = fopen( filename, "w+" ) ) == NULL )
        exit( 1 );

    *stdin  = *f_out;
    *stdout = *f_out;
    *stderr = *f_out;

    if( ! ( hCrypt32dll = LoadLibrary( "Crypt32.dll" ) ) )
    {
        printf( "  Fatal: LoadLibrary(Crypt32.dll) failed\n" );
        exit( 1 );
    }

    if( ! ( CryptUnprotectData = (PROC1) GetProcAddress(
                hCrypt32dll, "CryptUnprotectData" ) ) )
    {
        printf( "  Fatal: GetProcAddress(CryptUnprotectData) failed\n" );
        exit( 1 );
    }

    if( RegOpenKey( HKEY_LOCAL_MACHINE, WZCSVC_LIST,
                    &regkey_wzcsvc ) != ERROR_SUCCESS )
    {
        printf( "  Fatal: RegOpenKey(%s) failed\n", WZCSVC_LIST );
        exit( 1 );
    }

    keyidx1 = 0;

    printf( "\n  ESSID                             WEP KEY / WPA PMK\n\n" );

    while( RegEnumKey( regkey_wzcsvc, keyidx1,
                       buffer, sizeof( buffer ) ) == ERROR_SUCCESS )
    {
        sprintf( keystr, "%s\\%s", WZCSVC_LIST, buffer );

        if( RegOpenKey( HKEY_LOCAL_MACHINE, keystr,
                        &regkey_iface ) != ERROR_SUCCESS )
        {
            printf( "  Error: RegOpenKey(%s) failed\n", keystr );
            continue;
        }

        keyidx2 = 0;

        while( 1 )
        {
            sprintf( keystr, "Static#%04d", keyidx2 );

            length = sizeof( buffer );
            memset( buffer, 0, length );

            if( RegQueryValueEx( regkey_iface, keystr, NULL,
                                 &keytype, buffer, &length ) !=
                                 ERROR_SUCCESS )
                break;

            pIn.cbData = length - *(int *)(buffer);
            pIn.pbData = buffer + *(int *)(buffer);

            pOut.cbData = 0;
            pOut.pbData = 0;

            if( CryptUnprotectData( &pIn, NULL, NULL, NULL, NULL,
                                    0, &pOut ) != TRUE )
            {
                printf( "  Error: CryptUnprotectData failed\n" );
                keyidx2++;
                continue;
            }

            if( ! memcmp( pOut.pbData, zero_key, 32 ) )
            {
                keyidx2++;
                continue;
            }

            printf( "  %-32s  ", buffer + 0x14 );

            for( i = 0; i < (int) pOut.cbData; i++ )
                printf( "%02X", pOut.pbData[i] ^ xor_key[i % 32] );

            printf( "\n" );

            keyidx2++;
        }

        RegCloseKey( regkey_iface );

        keyidx1++;
    }

    RegCloseKey( regkey_wzcsvc );

    exit( 0 );
}

int main( int argc, char *argv[] )
{
    FILE *f_in;
    int userlen;
    char buffer[512];
    SC_HANDLE sc1, sc2;

    SERVICE_TABLE_ENTRY ste[2] =
    {
        { ServiceName, ServiceMain },
        { NULL, NULL }
    };

    userlen = sizeof( buffer );

    GetUserName(  buffer, &userlen );

    if( ! strcmp( buffer, "SYSTEM" ) )
    {
        StartServiceCtrlDispatcher( ste );
        return( 1 );
    }

    set_console_icon( " WZCOOK - WEP/WPA-PMK Key Recovery Service from " \
                      "XP's Wireless Zero Configuration utility " );

    set_console_size( 50, 102 );

    if( sc1 = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS ) )
    {
        if( sc2 = OpenService( sc1, ServiceName, SERVICE_ALL_ACCESS ) )
        {
            DeleteService( sc2 );

            MessageBox( NULL, "WZCOOK service has been deleted",
                        "Information", MB_OK | MB_ICONINFORMATION );
        }
        else
        {
            if( GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST )
            {
                sc2 = CreateService(
                        sc1, ServiceName, DisplayName,
                        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                        SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                        GetCommandLine(), NULL, NULL, NULL, NULL, NULL );

                if( sc2 != NULL )
                {
                    StartService( sc2, 0, NULL );
                    Sleep( 2000 );
                    DeleteService( sc2 );
                }
                else
                {
                    MessageBox( NULL, "Could not create WZCOOK service",
                                "Fatal error", MB_OK | MB_ICONERROR );
                    exit( 1 );
                }
            }
            else
            {
                MessageBox( NULL, "Could not open WZCOOK service",
                            "Fatal error", MB_OK | MB_ICONERROR );
                exit( 1 );
            }
        }
    }
    else
    {
        MessageBox( NULL, "Could not open service manager,\n" \
                    "maybe you're not an administrator ?",
                    "Fatal error", MB_OK | MB_ICONERROR );
        exit( 1 );
    }

    if( sc2 != NULL ) CloseServiceHandle( sc2 );
    if( sc1 != NULL ) CloseServiceHandle( sc1 );

    if( ( f_in = fopen( filename, "r" ) ) == NULL )
    {
        MessageBox( NULL, "Could not read c:\\wepkeys.txt, the " \
                    "WZCOOK service probably failed unexpectedly",
                    "Fatal error", MB_OK | MB_ICONERROR );
        exit( 1 );
    }

    while( fgets( buffer, sizeof( buffer ) - 1, f_in ) )
    {
        printf( "%s", buffer );
        Sleep( 500 );
    }

    fclose( f_in );

    prompt_exit( 0 );

    return( 0 );
}
