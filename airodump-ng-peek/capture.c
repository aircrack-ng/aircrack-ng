#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>

#include "capture.h"

typedef HANDLE (*PROC1)(LPSTR);
typedef HANDLE (*PROC2)(HANDLE,void *,int,int,void *);
typedef int (*PROC3)(HANDLE);
typedef int (*PROC4)(HANDLE,void *,void *);

HANDLE hAdapter;
HANDLE hContext;

PROC1 PeekOpenAdapter;
PROC2 PeekCreateCaptureContext;
PROC3 PeekStartCapture;
PROC3 PeekStopCapture;
PROC3 PeekCloseAdapter;
PROC4 PeekRequest;

int load_peek( void )
{
    HMODULE hPeekdll;


    if( ! ( hPeekdll = LoadLibrary( "Peek.dll" ) ) )
    {
        fprintf( stderr, "  LoadLibrary(Peek.dll) failed, make sure" \
                 " this file is present in the current directory.\n" );
        return( 1 );
    }

    if( ! ( PeekOpenAdapter = (PROC1) GetProcAddress(
                hPeekdll, "PeekOpenAdapterA" ) ) )
    {
        fprintf( stderr, "  GetProcAddress(PeekOpenAdapterA) failed\n" );
        return( 1 );
    }

    if( ! ( PeekCreateCaptureContext = (PROC2) GetProcAddress(
                hPeekdll, "PeekCreateCaptureContext" ) ) )
    {
        fprintf( stderr, "  GetProcAddress(PeekCreateCaptureContext) " \
                 "failed\n" );
        return( 1 );
    }


    if( ! ( PeekStartCapture = (PROC3) GetProcAddress(
                hPeekdll, "PeekStartCapture" ) ) )
    {
        fprintf( stderr, "  GetProcAddress(PeekStartCapture) failed\n" );
        return( 1 );
    }


    if( ! ( PeekRequest = (PROC4) GetProcAddress(
                hPeekdll, "PeekRequest" ) ) )
    {
        fprintf( stderr, "  GetProcAddress(PeekRequest) failed\n" );
        return( 1 );
    }


    if( ! ( PeekStopCapture = (PROC3) GetProcAddress(
                hPeekdll, "PeekStopCapture" ) ) )
    {
        fprintf( stderr, "  GetProcAddress(PeekStopCapture) failed\n" );
        return( 1 );
    }


    if( ! ( PeekCloseAdapter = (PROC3) GetProcAddress(
                hPeekdll, "PeekCloseAdapter" ) ) )
    {
        fprintf( stderr, "  GetProcAddress(PeekCloseAdapter) failed\n" );
        return( 1 );
    }

    return( 0 );
}

int show_cards( void )
{
    int keyidx;
    int keylen;
    int keytype;
    int nbcards;
    int card_index;
    char keystr[128];
    HKEY regkey1;
    HKEY regkey2;

    printf( "\n  Known network adapters:\n\n" );

    if( RegOpenKey( HKEY_LOCAL_MACHINE, "Software\\Microsoft\\"
                    "Windows NT\\CurrentVersion\\NetworkCards",
                    &regkey1 ) != ERROR_SUCCESS )
    {
        fprintf( stderr, "  RegOpenKey(KEY_LOCAL_MACHINE\\Software\\"
                         "Microsoft\\Windows NT\\CurrentVersion\\"
                         "NetworkCards) failed\n" );
        return( 0 );
    }

    nbcards = keyidx = 0;

    while( RegEnumKey( regkey1, keyidx++, keystr, 128 ) == ERROR_SUCCESS )
    {
        card_index = atoi( keystr );

        sprintf( keystr, "Software\\Microsoft\\Windows NT\\Current"
                         "Version\\NetworkCards\\%d", card_index );

        if( RegOpenKey( HKEY_LOCAL_MACHINE, keystr, &regkey2 ) !=
                        ERROR_SUCCESS )
        {
            fprintf( stderr, "  RegOpenKey(KEY_LOCAL_MACHINE\\Software\\"
                             "Microsoft\\Windows NT\\CurrentVersion\\"
                             "NetworkCards\\%d) failed\n", card_index );
            continue;
        }

        keylen = sizeof( keystr );

        if( RegQueryValueEx( regkey2, "Description", NULL,
                             &keytype, keystr, &keylen ) !=
                             ERROR_SUCCESS )
        {
            RegCloseKey( regkey2 );

            fprintf( stderr, "  RegOpenKey(KEY_LOCAL_MACHINE\\Software\\"
                             "Microsoft\\Windows NT\\CurrentVersion\\"
                             "NetworkCards\\%d\\Description) failed\n",
                             card_index );
            continue;
        }

        RegCloseKey( regkey2 );

        if( open_adapter( card_index ) != 0 )
            continue;

        PeekCloseAdapter( hAdapter );

        printf( "  %2d  %s\n", card_index, keystr );

        nbcards++;
    }

    RegCloseKey( regkey1 );

    if( nbcards > 0 ) printf( "\n" );

    return( nbcards );
}

int set_channel( int channel )
{
    unsigned long reqdata[139];
    OVERLAPPED iodata;

    memset( (void *) reqdata, 0, sizeof( reqdata ) );
    memset( (void *) &iodata, 0, sizeof(  iodata ) );

    iodata.hEvent = CreateEvent( 0, 0, 0, 0 );

    reqdata[5] = 1;
    reqdata[6] = 0xFF636713;
    reqdata[7] = (unsigned long) &channel;
    reqdata[8] = 4;

    return( PeekRequest( hAdapter, reqdata, &iodata ) );
}

int open_adapter( int card_index )
{
    int keylen;
    int keytype;
    char keystr[128];
    char devstr[128];
    HKEY regkey2;

    sprintf( keystr, "Software\\Microsoft\\Windows NT\\Current"
                     "Version\\NetworkCards\\%d", card_index );

    if( RegOpenKey( HKEY_LOCAL_MACHINE, keystr, &regkey2 ) !=
                    ERROR_SUCCESS )
        return( 1 );

    keylen = sizeof( keystr );

    if( RegQueryValueEx( regkey2, "ServiceName", NULL,
                         &keytype, keystr, &keylen ) !=
                         ERROR_SUCCESS )
    {
        fprintf( stderr, "  RegOpenKey(KEY_LOCAL_MACHINE\\Software\\"
                         "Microsoft\\Windows NT\\CurrentVersion\\"
                         "NetworkCards\\%d\\ServiceName) failed!\n",
                         card_index );
        return( 1 );
    }

    sprintf( devstr, "\\Device\\%s", keystr );

    hAdapter = PeekOpenAdapter( devstr );

    return( hAdapter == INVALID_HANDLE_VALUE );
}

int start_monitor( void *callback )
{
    int ret;

    if( hAdapter == INVALID_HANDLE_VALUE )
    {
        fprintf( stderr, "  Invalid adapter handle\n" );
        return( 1 );
    }

    hContext = PeekCreateCaptureContext( hAdapter, callback,
                                         0x3E8000, 0x21, NULL );

    if( PeekStartCapture( hContext ) != 0 )
    {
        PeekCloseAdapter( hAdapter );

        fprintf( stderr, "  PeekStartCapture() failed\n" );
        return( 1 );
    }

    ret = set_channel( 1 );

    if( ret == 0xC0010017 )
    {
        PeekStopCapture( hContext );
        PeekCloseAdapter( hAdapter );

        fprintf( stderr, "\n  The selected adapter's driver is not com" \
                         "patible with the PEEK protocol. See the\n  "  \
                         "aircrack documentation for more information"  \
                         " on how to install a compatible driver.\n\n"  \
                         "  Only Atheros, Aironet, Realtek (RTL8180) "  \
                         "and HermesI chipsets have a Peek driver.\n"   \
                         "  There is NO Peek driver AT ALL for Prism,"  \
                         " Ralink, Marvel, TI or Centrino chipsets.\n" );

        ShellExecute( NULL, "OPEN", "http://www.wildpackets.com/"
                      "support/product_support/airopeek/hardware",
                      "", "", SW_SHOWNORMAL );

        return( 1 );
    }

    if( ret != 0 )
    {
        PeekStopCapture( hContext );
        PeekCloseAdapter( hAdapter );

        fprintf( stderr, "  FATAL: failed to set the wireless channel, "\
                         "is something wrong with the card?\n" );
		fprintf( stderr, "  Also make sure you have installed the correct "
			             "driver.\n" );
        return( 1 );
    }

    return( 0 );
}

void stop_monitor( void )
{
    PeekStopCapture( hContext );
    Sleep( 1000 );
    PeekCloseAdapter( hAdapter );
}
