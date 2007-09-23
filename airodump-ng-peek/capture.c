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


#define PEEK_INSTALLED_KEY "SOFTWARE\\Airodump-ng"

unsigned char * download(const char * url, const int buffsize)
{
    HINTERNET a,b;
    DWORD size;
    BOOL result;
    unsigned char * buffer;
    static char * err = "Failed to download Peek files, exiting";
    if (!(a = InternetOpen("Internet Explorer 6.0",
    	INTERNET_OPEN_TYPE_PRECONFIG,NULL,NULL,0)))
    {
       InternetCloseHandle(a);
       MessageBox(NULL, err, "Airodump-ng", MB_OK | MB_ICONERROR);
       exit(-1);
    }
    if (!(b=InternetOpenUrl(a,url, NULL,0,0,0)))
    {
       InternetCloseHandle(a);
       InternetCloseHandle(b);
       MessageBox(NULL, err, "Airodump-ng", MB_OK | MB_ICONERROR);
       exit(-1);
    }
    buffer = (unsigned char * ) calloc(1,buffsize);
    size = 0;
    result = InternetReadFile(b, buffer, buffsize, &size);
    InternetCloseHandle(a);
    InternetCloseHandle(b);
    if (size && result == TRUE)
		return buffer;

    /* Error happened */
    MessageBox(NULL, err, "Airodump-ng", MB_OK | MB_ICONERROR);
    return buffer;
}

int file_exist( const char * filename, int size )
{
	FILE * f;
	long filesize = 0;
	f = fopen(filename, "rb");
	if (f == NULL)
		return 1;
	if (size < 0)
		return 1;
	fseek(f, 0, SEEK_END);
	filesize = ftell(f);
	fclose(f);
	if ((int)filesize == size)
		return 0;
	else
		return 1;
}

int downloadFile(const char * filename, const char * url, int size)
{
	unsigned char * content;
	FILE * f;

	if (size <= 0)
		return 1;

	if (file_exist( filename, size ) != 0 )
	{
		content = download(url, size);
		f = fopen(filename, "wb");
		if (f == NULL)
		{
			perror("Failed to create file");
			return 1;
		}

		fwrite (content, 1, size, f);
		fclose (f);
	}
	return 0;
}

int regkeyExist( void )
{
	HKEY key;
	int keyExist = 0;

	if( RegOpenKey( HKEY_LOCAL_MACHINE, PEEK_INSTALLED_KEY,
                    &key ) == ERROR_SUCCESS )
	{
		// Close key
		RegCloseKey(key);
		
		keyExist = 1;
	}

	return keyExist;
}

int regkeyCreate( void )
{
	HKEY key;
	int success = 0;

	// Create key 
	if (RegCreateKey( HKEY_LOCAL_MACHINE, 
		PEEK_INSTALLED_KEY, &key ) != ERROR_SUCCESS)
	{
		perror("RegCreateKey()");
	}
	else
	{
		success = 1;

		// Close key
		RegCloseKey(key);
	}

	return success;
}

void installed_peek_drivers( void )
{
	int result;

	// Check if user already installed the driver
	if (regkeyExist() == 0)
	{
		// Show messagebox
		result = MessageBox(NULL, 
						"Do you want the peek (from wildpackets) drivers installed?\n"
						"Clicking on \"No\" assume you have it installed.\n"
						"Clicking on \"Yes\" will open a browser on the driver download page.",
						"Airodump-ng", MB_YESNO | MB_ICONQUESTION);

		// Click on Yes
		if (result == IDYES)
		{
			// Open a browser on wildpacket web page
			ShellExecute(NULL, "open", "http://www.wildpackets.com/support/downloads/drivers",
                NULL, NULL, SW_SHOWNORMAL);

			exit(-1);
		}
		
		// Else, click on "No" -> Drivers are supposed to be installed.

		// Create a registry key so that the user isn't prompted anymore
		regkeyCreate();
	}
}

int load_peek( void )
{
    HMODULE hPeekdll;

	installed_peek_drivers();

	downloadFile("Peek.dll", "http://www.personalwireless.org/tools/aircrack/Peek.dll", 24064);
	downloadFile("Peek5.sys", "http://www.personalwireless.org/tools/aircrack/Peek5.sys", 13184);

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
