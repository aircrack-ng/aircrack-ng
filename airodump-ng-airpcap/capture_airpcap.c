#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <airpcap.h>

#include "capture.h"

PAirpcapHandle airpcap_ad;
pcap_t *winpcap_ad;
int ppi_decode(const u_char *p, int caplen, int *hdrlen, int *power);

#define PPH_PH_VERSION		((u_int8_t)0x00)
#define	PPI_FIELD_TYPE_802_11_COMMON		((u_int16_t)0x02)

#pragma pack(push)
#pragma pack(1)

typedef struct _PPI_PACKET_HEADER
{
	u_int8_t	PphVersion;
	u_int8_t	PphFlags;
	u_int16_t	PphLength;
	u_int32_t	PphDlt;
}
PPI_PACKET_HEADER, *PPPI_PACKET_HEADER;

typedef struct _PPI_FIELD_HEADER
{
	u_int16_t PfhType;
	u_int16_t PfhLength;
}
PPI_FIELD_HEADER, *PPPI_FIELD_HEADER;

typedef struct _PPI_FIELD_802_11_COMMON
{
	u_int64_t	TsfTimer;
	u_int16_t	Flags;
	u_int16_t	Rate;
	u_int16_t	ChannelFrequency;
	u_int16_t	ChannelFlags;
	u_int8_t	FhssHopset;
	u_int8_t	FhssPattern;
	int8_t		DbmAntSignal;
	int8_t		DbmAntNoise;
}
PPI_FIELD_802_11_COMMON, *PPPI_FIELD_802_11_COMMON;
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

	if( !AirpcapSetLinkType( airpcap_ad, AIRPCAP_LT_802_11_PLUS_PPI ) )
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
	int hdrlen;
	int ppipower;

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

	ppi_decode(( char * )pkt_data, header->caplen, &hdrlen, &ppipower);

	*payload = ( char * )pkt_data + hdrlen;
	*caplen = header->caplen - hdrlen;
	if( header->caplen > 14 )
	{
		// Yes this is a hack.
		// But it's based on the assumption that radiotap header from AirPcap will be stable, which is
		// going to be true at least for the part before the power information.
		*power = ppipower;
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

int ppi_decode(const u_char *p, int caplen, int *hdrlen, int *power)
{
	PPPI_PACKET_HEADER pPpiPacketHeader;
	PPPI_FIELD_HEADER	pFieldHeader;
	ULONG position = 0;

	// Sanity checks
	if (caplen < sizeof(*pPpiPacketHeader))
	{
		// Packet smaller than the PPI fixed header
		return( 1 );
	}

	pPpiPacketHeader = (PPPI_PACKET_HEADER)p;

	*hdrlen = pPpiPacketHeader->PphLength;

	if(caplen < *hdrlen)
	{
		// Packet smaller than the PPI fixed header
		return( 1 );
	}

	position = sizeof(*pPpiPacketHeader);

	if (pPpiPacketHeader->PphVersion != PPH_PH_VERSION)
	{
		fprintf( stderr, "Unknown PPI packet header version (%u)\n", pPpiPacketHeader->PphVersion);
		return( 1 );
	}

	do
	{
		//
		// now we suppose to have an 802.11-Common header
		//
		if (*hdrlen < sizeof(*pFieldHeader) + position)
		{
			break;
		}

		pFieldHeader = (PPPI_FIELD_HEADER)(p + position);
		position += sizeof(*pFieldHeader);

		switch(pFieldHeader->PfhType)
		{
		case PPI_FIELD_TYPE_802_11_COMMON:
			if (pFieldHeader->PfhLength != sizeof(PPI_FIELD_802_11_COMMON) || caplen - position < sizeof(PPI_FIELD_802_11_COMMON))
			{
				//
				// the header is bogus, just skip it
				//
				fprintf( stderr, "Bogus 802.11-Common Field. Skipping it.\n");
			}
			else
			{
				PPPI_FIELD_802_11_COMMON pField = (PPPI_FIELD_802_11_COMMON)(p + position);

				if (pField->DbmAntSignal != -128)
				{
					*power = (int)pField->DbmAntSignal;
				}
				else
				{
					*power = 0;
				}
			}
			break;

		default:
			// we do not know this field. Just print type and length and skip
			break;
		}

		position += pFieldHeader->PfhLength;
	}
	while(TRUE);

	return( 0 );
}