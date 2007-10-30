#include <airpcap.h>

// Function to be used by cygwin
int airpcap_set_mac(unsigned char *mac);
void airpcap_close(void);
int airpcap_get_mac(unsigned char *mac);
int airpcap_sniff(void *buf, int len, struct rx_info *ri);
int airpcap_inject(void *buf, int len, struct tx_info *ti);
int airpcap_init(char *param);
int airpcap_set_chan(int chan);

//------------------ PPI ---------------------
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

static int ppi_decode(const u_char *p, int caplen, int *hdrlen, int *power);
//------------------ PPI ---------------------

static const char * DEFAULT_ADAPT_NAME = "\\\\.\\airpcap00";
static const char * DEVICE_HEADER = "\\\\.\\";
static const char * DEVICE_COMMON_PART "airpcap"

static PAirpcapHandle airpcap_handle;

static int printErrorCloseAndReturn(const char * err, int retValue);
int isAirpcapDevice(const char * iface);