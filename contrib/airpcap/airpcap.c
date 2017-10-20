#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

#include <airpcap.h>

#include "osdep.h"
#include "tap-win32/common.h"

static const char * DEFAULT_ADAPT_NAME = "\\\\.\\airpcap00";
static const char * DEVICE_HEADER = "\\\\.\\";


//pcap_t *winpcap_adapter;
static PAirpcapHandle airpcap_handle;


// Use PPI later
#define PPH_PH_VERSION		((u_int8_t)0x00)
#define	PPI_FIELD_TYPE_802_11_COMMON		((u_int16_t)0x02)

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



static int ppi_decode(const u_char *p, int caplen, int *hdrlen, int *power)
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
		// now we suppose to have an 802.11-Common header
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
					// the header is bogus, just skip it
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


int cygwin_set_mac(unsigned char *mac)
{
   	if (*mac) {}
   	return 0;
}

void cygwin_close(void)
{
	// By default, when plugged in, the adapter is set in monitor mode;
	// Application may assume it's already in monitor mode and forget to set it
	// So, do not remove monitor mode.
	if (airpcap_handle != NULL)
	{
		AirpcapClose(airpcap_handle);
	}
}

int cygwin_get_mac(unsigned char *mac)
{
   // Don't use the function from Airpcap
	if (*mac) {}

	return 0;
}

// Use PPI headers to obtain the different information for ri
// Use AirpcapConvertFrequencyToChannel() to get channel
// Add an option to give frequency instead of channel
int cygwin_sniff(void *buf, int len, struct rx_info *ri)
{
	UINT BytesReceived = 0;

	// Wait for the next packet
	// Maybe add an event packets to read
	// WaitForSingleObject(ReadEvent, INFINITE);

	// Read a packet
	if(AirpcapRead(airpcap_handle, buf, len, &BytesReceived))
		return (int)BytesReceived;

	return -1;
}

int cygwin_inject(void *buf, int len, struct tx_info *ti)
{
	if (AirpcapWrite (airpcap_handle, buf, len) != 1)
		return -1;

	return len;
}

static int printErrorCloseAndReturn(const char * err, int retValue)
{
	if (err && airpcap_handle)
	{
		if (strlen(err))
		{
			if (airpcap_handle)
				fprintf( stderr, err, AirpcapGetLastError(airpcap_handle));
			else
				fprintf( stderr, err);
		}
	}

	cygwin_close();

    return retValue;
}

int cygwin_init(char *param)
{
	char * iface;
    char errbuf[AIRPCAP_ERRBUF_SIZE ];

	iface = (char *)calloc(1, strlen(param) + strlen(DEVICE_HEADER) +1);
	strcpy (iface, DEFAULT_ADAPT_NAME);

	if (param)
	{
		// if it's empty, use the default adapter
		if (strlen(param) > 0)
		{
			// Make sure the adapter name contains the '\\.\' at its beginning
			memset(iface, 0, strlen(param) + strlen(DEVICE_HEADER) +1);

			if (strstr(param, DEVICE_HEADER) == NULL)
			{
				// Not found, add it

				strcpy(iface, DEVICE_HEADER);
				strcat(iface, param);
			}
			else
			{
				// Already contains the adapter header
				strcpy(iface, param);
			}
		}
	}

    airpcap_handle = AirpcapOpen(iface, errbuf);

    if(airpcap_handle == NULL)
    {
        fprintf( stderr, "This adapter doesn't have wireless extensions. Quitting\n");
        //pcap_close( winpcap_adapter );
        return( -1 );
    }

    /* Tell the adapter that the packets we'll send and receive don't include the FCS */
    if(!AirpcapSetFcsPresence(airpcap_handle, FALSE))
		return printErrorCloseAndReturn("Error setting FCS presence: %s\n", -1);

    /* Set the link layer to bare 802.11 */
    if(!AirpcapSetLinkType(airpcap_handle, AIRPCAP_LT_802_11))
		return printErrorCloseAndReturn("Error setting the link type: %s\n", -1);

    /* Accept correct frames only */
	if( !AirpcapSetFcsValidation(airpcap_handle, AIRPCAP_VT_ACCEPT_CORRECT_FRAMES) )
		return printErrorCloseAndReturn("Error setting FCS validation: %s\n", -1);

    /* Set a low mintocopy for better responsiveness */
    if(!AirpcapSetMinToCopy(airpcap_handle, 1))
		return printErrorCloseAndReturn("Error setting MinToCopy: %s\n", -1);

	return 0;
}

int cygwin_set_chan(int chan)
{
	// Make sure a valid channel is given
	if (chan <= 0)
		return -1;

	if(!AirpcapSetDeviceChannel(airpcap_handle, chan))
	{
		printf("Error setting the channel to %d: %s\n", chan, AirpcapGetLastError(airpcap_handle));
		return -1;
	}

	return 0;
}
