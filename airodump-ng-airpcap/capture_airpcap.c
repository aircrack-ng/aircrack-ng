#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <airpcap.h>

#include "capture.h"

typedef HANDLE (*PROC1)(LPSTR);
typedef HANDLE (*PROC2)(HANDLE,void *,int,int,void *);
typedef int (*PROC3)(HANDLE);
typedef int (*PROC4)(HANDLE,void *,void *);

PAirpcapHandle airpcap_ad;
pcap_t *winpcap_ad;

#pragma pack(push)

#pragma pack(1)
typedef struct _ieee80211_radiotap_header 
{
	u_int8_t it_version;
	u_int8_t it_pad;
	u_int16_t it_len;
	u_int32_t it_present;
}
ieee80211_radiotap_header;

#pragma pack(pop)


int show_cards( void )
{
    int nbcards = 0;
	AirpcapDeviceDescription *alldevs, *tmpdev;
	CHAR ebuf[AIRPCAP_ERRBUF_SIZE];

    printf( "\n  Known network adapters:\n\n" );

	if( !AirpcapGetDeviceList( &alldevs, ebuf ) )
	{
		fprintf( stderr, "Unable to retrieve the device list: %s\n", ebuf );
		return -1;
	}

	for( tmpdev = alldevs, nbcards = 0; tmpdev; tmpdev = tmpdev->next )
	{
        fprintf( stderr,  "  %2d  %s\n", ++nbcards, tmpdev->Description );
	}

    if( nbcards > 0 ) printf( "\n" );

	AirpcapFreeDeviceList(alldevs);

    return( nbcards );
}

int set_channel( int channel )
{
	if(!AirpcapSetDeviceChannel(airpcap_ad, channel))
	{
		fprintf( stderr, "Error setting the channel: %s\n", AirpcapGetLastError(airpcap_ad));
		return( 1 );
	}

	return( 1 );
}

int open_adapter( int card_index )
{
	int i;
	CHAR ebuf[max(AIRPCAP_ERRBUF_SIZE, PCAP_ERRBUF_SIZE)];
	AirpcapDeviceDescription *alldevs, *tmpdev;

	if( !AirpcapGetDeviceList( &alldevs, ebuf ) )
	{
		fprintf( stderr,  "Unable to retrieve the device list: %s\n", ebuf );
		return ( 1 );
	}

	if( !alldevs )
	{
		fprintf( stderr,  "No airpcap devices found on this machine\n" );
		return ( 1 );
	}

	for( tmpdev = alldevs, i = 0; i < card_index - 1; tmpdev = tmpdev->next, i++ );

	if( ( winpcap_ad = pcap_open_live( tmpdev->Name,
		65536,										
													
		1,											
		100,										
		ebuf										
		) ) == NULL )
	{
		fprintf( stderr, "Error opening adapter with winpcap (%s)\n", ebuf );
		AirpcapFreeDeviceList( alldevs );
		return ( 1 );
	}

	AirpcapFreeDeviceList( alldevs );

	airpcap_ad = pcap_get_airpcap_handle(winpcap_ad);

	if( airpcap_ad == NULL )
	{
		fprintf( stderr, "This adapter doesn't have wireless extensions. Quitting\n" );
		pcap_close( winpcap_ad );
		return ( 1 );
	}

	if( !AirpcapSetLinkType( airpcap_ad, AIRPCAP_LT_802_11_PLUS_RADIO ) )
	{
		fprintf( stderr, "Error setting the link layer: %s\n", AirpcapGetLastError( airpcap_ad ) );
		pcap_close( winpcap_ad );
		return ( 1 );
	}

	if( !AirpcapSetFcsPresence( airpcap_ad, FALSE) )
	{
		fprintf( stderr, "Error setting the fcs presence: %s\n", AirpcapGetLastError( airpcap_ad ) );
		pcap_close( winpcap_ad );
		return ( 1 );
	}

	if( !AirpcapSetFcsValidation( airpcap_ad, AIRPCAP_VT_ACCEPT_CORRECT_FRAMES) )
	{
		fprintf( stderr, "Error setting the fcs validation: %s\n", AirpcapGetLastError( airpcap_ad ) );
		pcap_close( winpcap_ad );
		return ( 1 );
	}

    return( 0 );
}

int GetNextPacket( char **payload, int *caplen, char *power)
{
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int res;
	ieee80211_radiotap_header *rt;

	res = pcap_next_ex( winpcap_ad, &header, &pkt_data );
	
	if( res < 0 )
	{
		// error
		fprintf( stderr, "Error reading the packets: %s\n", pcap_geterr( winpcap_ad ) );
		return ( 1 );
	}

	if( res == 0 )
	{
		// Timeout elapsed
		*payload = NULL;
		*caplen = 0;
		*power = 0;
		return( 1 );
	}

	rt = (ieee80211_radiotap_header*)pkt_data;

	*payload = ( char * )pkt_data + rt->it_len;
	*caplen = header->caplen - rt->it_len;
	if( header->caplen > 14 )
	{
		// Yes this is a hack. 
		// But it's based on the assumption that radiotap header from AirPcap will be stable, which is
		// going to be true at least for the part before the power information.
		*power = pkt_data[14];
	}

	return( 0 );
}

int start_monitor( void *callback )
{
    return( 0 );
}

void stop_monitor( void )
{
}
