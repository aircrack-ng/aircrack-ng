#ifndef _COMMON_H
#define _COMMON_H

#define FORMAT_CAP      1
#define FORMAT_IVS      2

#define PCAP_ERRBUF_SIZE 256

#define TCPDUMP_MAGIC           0xA1B2C3D4
#define TCPDUMP_CIGAM           0xD4C3B2A1
#define IVSONLY_MAGIC           "\xBF\xCA\x84\xD4"

#define PCAP_VERSION_MAJOR      2
#define PCAP_VERSION_MINOR      4

#define LINKTYPE_ETHERNET       1
#define LINKTYPE_IEEE802_11     105
#define LINKTYPE_PRISM_HEADER   119
#define LINKTYPE_RADIOTAP_HDR   127

#define uchar  unsigned char
#define ushort unsigned short
#define uint   unsigned int
#define ulong  unsigned long

#define SWAP32(x)       \
    x = ( ( ( x >> 24 ) & 0x000000FF ) | \
          ( ( x >>  8 ) & 0x0000FF00 ) | \
          ( ( x <<  8 ) & 0x00FF0000 ) | \
          ( ( x << 24 ) & 0xFF000000 ) );

struct pcap_file_header
{
    uint magic;
    ushort version_major;
    ushort version_minor;
    int thiszone;
    uint sigfigs;
    uint snaplen;
    uint linktype;
};

struct pcap_pkthdr
{
    int tv_sec;
    int tv_usec;
    uint caplen;
    uint len;
};

typedef struct pcap pcap_t;

#ifdef WIN32
pcap_t	*pcap_open_live(const char *, int, int, int, char *);
void	pcap_close(pcap_t *);
PAirpcapHandle pcap_get_airpcap_handle(pcap_t *p);
int	pcap_sendpacket(pcap_t *, const u_char *, int);
char	*pcap_geterr(pcap_t *);
int 	pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const u_char **);
#endif /* WIN32 */
#endif /* common.h */
