#include <string.h>
#include <stdlib.h>
#include <stdio.h>
//#include <unistd.h>
//#include <fcntl.h>
//#include <wchar.h>

#include <windows.h>

#include <airpcap.h>

#include "osdep.h"
#include "tap-win32/common.h"

const char * DEF_ADAPT_NAME = "\\\\.\\airpcap00";
const char * ADAPT_HEADER = "\\\\.\\";

PAirpcapHandle device_Handle = NULL;
CHAR Ebuf[AIRPCAP_ERRBUF_SIZE];
BYTE* PacketBuffer;
UINT BytesReceived;
HANDLE ReadEvent;


#define LASTERR AirpcapGetLastError(device_Handle)
#define CLOSE_ADAPTER AirpcapClose(device_Handle);

int cygwin_set_mac(unsigned char *mac)
{
   if (*mac) {}
   return 0;
}

void cygwin_close(void)
{
	// Do not remove monitor mode in case another application forget to set it
	// (by default, when plugged in, the adapter is set in monitor mode)
	if (device_Handle != NULL)
		CLOSE_ADAPTER;
}

int cygwin_get_mac(unsigned char *mac)
{
   // Don't use the function from Airpcap

   return 0;
}

int cygwin_sniff(void *buf, int len, struct rx_info *ri)
{
	UINT BytesReceived = 0;
	UINT channel = 0;

	// Wait for the next packet
	WaitForSingleObject(ReadEvent, INFINITE);

	// Read a packet
	if(AirpcapRead(device_Handle, buf, len, &BytesReceived))
	{
		if (ri)
		{
			// Try getting channel
			if (AirpcapGetDeviceChannel(device_Handle, &channel))
			{
				ri->ri_channel = (int)channel;
			}
			// Don't complain if it fails
		}
		return (int)BytesReceived;
	}

	// It failed, return -1
	printf("Error receiving packets: %s\n", LASTERR);
	return -1;
}

int cygwin_inject(void *buf, int len, struct tx_info *ti)
{
	if (buf)
	{
		if (AirpcapWrite(device_Handle, buf, len) == FALSE)
			return -1;
		else
			return len;
	}
}

int cygwin_init(char *param)
{
	char * adapter;

	adapter = (char *)calloc(1, strlen(param) + strlen(ADAPT_HEADER) +1);
	strcpy (adapter, DEF_ADAPT_NAME);

	if (param)
	{
		// if it's empty, use the default adapter
		if (strlen(param) > 0)
		{
			// Make sure the adapter name contains the '\\.\' at its begining
			if (strstr(param, ADAPT_HEADER) == NULL)
			{
				// Not found, add it
				memset(adapter, 0, strlen(param) + strlen(ADAPT_HEADER) +1);
				strcpy(adapter, ADAPT_HEADER);
				strcat(adapter, param);
			}
			else
			{
				// Already contains the adapter header
				free(adapter);
				adapter = param;
			}
		}
	}

	// Open the adapter
	device_Handle = AirpcapOpen(adapter, Ebuf);

	if (device_Handle == NULL  )
	{
		printf("Error opening adapter: %s\n", LASTERR);
		return -1;
	}


	// Set monitor mode
	if(!AirpcapSetMonitorMode(device_Handle, TRUE))
	{
		printf("Error turning monitor mode on: %s\n", adapter);
		return -1;
	}


	// Set the link layer to 802.11
	if(!AirpcapSetLinkType(device_Handle, AIRPCAP_LT_802_11))
	{
		printf("Error setting the link layer: %s\n", LASTERR);
		return -1;
	}

	// Remove FCS
	if (AirpcapSetFcsPresence(device_Handle, FALSE) == FALSE)
	{
		printf("Error disabling FCS presence. Error: %s\n", LASTERR);
		return -1;
	}

	// Only get valid frames
	if (AirpcapSetFcsValidation(device_Handle,
		//AirpcapValidationType.AIRPCAP_VT_ACCEPT_CORRECT_FRAMES) == FALSE)
		AIRPCAP_VT_ACCEPT_CORRECT_FRAMES) == FALSE)
	{
		printf("Error setting FCS validation. Error: %s\n", LASTERR);
		return -1;
	}

	// Add read event
	if (AirpcapGetReadEvent(device_Handle, &ReadEvent) == FALSE)
	{
		printf("Error getting the read event: %s\n", LASTERR);
		return -1;
	}

	AirpcapSetMinToCopy(device_Handle, 1);

	return 0;
}

int cygwin_set_chan(int chan)
{
	// Make sure a valid channel is given
	if (chan <= 0)
		return -1;

	if(!AirpcapSetDeviceChannel(device_Handle, chan))
	{
		printf("Error setting the channel to %d: %s\n", chan, LASTERR);
		return -1;
	}

	return 0;
}
