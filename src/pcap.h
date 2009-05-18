#ifndef _COMMON_H
#define _COMMON_H

#define FORMAT_CAP      1
#define FORMAT_IVS      2
#define FORMAT_IVS2     3

#define TCPDUMP_MAGIC           0xA1B2C3D4
#define TCPDUMP_CIGAM           0xD4C3B2A1
#define IVSONLY_MAGIC           "\xBF\xCA\x84\xD4"
#define IVS2_MAGIC              "\xAE\x78\xD1\xFF"
#define IVS2_EXTENSION		"ivs"
#define IVS2_VERSION             1

#define PCAP_VERSION_MAJOR      2
#define PCAP_VERSION_MINOR      4

#define LINKTYPE_ETHERNET       1
#define LINKTYPE_IEEE802_11     105
#define LINKTYPE_PRISM_HEADER   119
#define LINKTYPE_RADIOTAP_HDR   127
#define LINKTYPE_PPI_HDR		192

#define uchar  unsigned char
#define ushort unsigned short
#define uint   unsigned int
#define ulong  unsigned long

#define SWAP32(x)       \
    x = ( ( ( x >> 24 ) & 0x000000FF ) | \
          ( ( x >>  8 ) & 0x0000FF00 ) | \
          ( ( x <<  8 ) & 0x00FF0000 ) | \
          ( ( x << 24 ) & 0xFF000000 ) );

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define	le16_to_cpu(x) (x)
#else
#define	le16_to_cpu(x) ((((x)&0xff)<<8)|(((x)&0xff00)>>8))
#endif

//BSSID const. length of 6 bytes; can be together with all the other types
#define IVS2_BSSID	0x0001

//ESSID var. length; alone, or with BSSID
#define IVS2_ESSID	0x0002

//wpa structure, const. length; alone, or with BSSID
#define IVS2_WPA	0x0004

//IV+IDX+KEYSTREAM, var. length; alone or with BSSID
#define IVS2_XOR	0x0008

/* [IV+IDX][i][l][XOR_1]..[XOR_i][weight]                                                        *
 * holds i possible keystreams for the same IV with a length of l for each keystream (l max 32)  *
 * and an array "int weight[16]" at the end                                                      */
#define IVS2_PTW        0x0010

//unencrypted packet
#define IVS2_CLR        0x0020

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

struct ivs2_filehdr
{
    unsigned short version;
};

struct ivs2_pkthdr
{
    unsigned short  flags;
    unsigned short  len;
};

#endif /* common.h */
