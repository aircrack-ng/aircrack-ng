#include <stdint.h>

static const uint32_t crc32_ccitt_table[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419,
    0x706af48f, 0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4,
    0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07,
    0x90bf1d91, 0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
    0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 0x136c9856,
    0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4,
    0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3,
    0x45df5c75, 0xdcd60dcf, 0xabd13d59, 0x26d930ac, 0x51de003a,
    0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599,
    0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190,
    0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f,
    0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2, 0x0f00f934, 0x9609a88e,
    0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed,
    0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3,
    0xfbd44c65, 0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
    0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a,
    0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5,
    0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa, 0xbe0b1010,
    0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17,
    0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6,
    0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615,
    0x73dc1683, 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
    0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, 0xf00f9344,
    0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a,
    0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1,
    0xa6bc5767, 0x3fb506dd, 0x48b2364b, 0xd80d2bda, 0xaf0a1b4c,
    0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef,
    0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe,
    0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31,
    0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0, 0xec63f226, 0x756aa39c,
    0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b,
    0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1,
    0x18b74777, 0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
    0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45, 0xa00ae278,
    0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7,
    0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66,
    0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605,
    0xcdd70693, 0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8,
    0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b,
    0x2d02ef8d
};

struct net_hdr {
    uint8_t     nh_type;
    uint32_t    nh_len;
    uint8_t     nh_data[0];
} __packed;


struct llc_frame {
    u_int8_t    i_dsap;
    u_int8_t    i_ssap;
    u_int8_t    i_ctrl;
    u_int8_t    i_org[3];
    u_int16_t   i_ethtype;
} __attribute__((packed));

struct wep_frame {
    u_int8_t    iv1;
    u_int8_t    iv2;
    u_int8_t    iv3;
    u_int8_t    keyid;
} __attribute__((packed));

struct ip_frame {
    u_int8_t    ver;
    u_int8_t    tos;
    u_int16_t   tot_len;
    u_int16_t   id;
    u_int16_t   frag_off;
    u_int8_t    ttl;
    u_int8_t    protocol;
    u_int16_t   check;
    u_int32_t   saddr;
    u_int32_t   daddr;
} __attribute__((packed));

struct udp_hdr {
  u_int16_t sport;
  u_int16_t dport;
  u_int16_t len;
  u_int16_t checksum;
} __attribute__((packed));

struct tcp_hdr {
  u_int16_t sport;
  u_int16_t dport;
  u_int32_t seqnu;
  u_int32_t ack_seq;
  //u_int16_t len_flags;
  u_int16_t res1:4,
            doff:4,
            fin:1,
            syn:1,
            rst:1,
            psh:1,
            ack:1,
            urg:1,
            ece:1,
            cwr:1;
  u_int16_t window;
  u_int16_t checksum;
  u_int16_t urg_ptr;
} __attribute__((packed));

/*
 * Internal of an ICMP Router Advertisement
 */
struct icmp_ra_addr
{
  u_int32_t ira_addr;
  u_int32_t ira_preference;
};

struct icmp
{
  u_int8_t  icmp_type;  /* type of message, see below */
  u_int8_t  icmp_code;  /* type sub code */
  u_int16_t icmp_cksum; /* ones complement checksum of struct */
  union
  {
    u_char ih_pptr;     /* ICMP_PARAMPROB */
    struct in_addr ih_gwaddr;   /* gateway address */
    struct ih_idseq     /* echo datagram */
    {
      u_int16_t icd_id;
      u_int16_t icd_seq;
    } ih_idseq;
    u_int32_t ih_void;

    /* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
    struct ih_pmtu
    {
      u_int16_t ipm_void;
      u_int16_t ipm_nextmtu;
    } ih_pmtu;

    struct ih_rtradv
    {
      u_int8_t irt_num_addrs;
      u_int8_t irt_wpa;
      u_int16_t irt_lifetime;
    } ih_rtradv;
  } icmp_hun;

#define icmp_pptr   icmp_hun.ih_pptr
#define icmp_gwaddr icmp_hun.ih_gwaddr
#define icmp_id     icmp_hun.ih_idseq.icd_id
#define icmp_seq    icmp_hun.ih_idseq.icd_seq
#define icmp_void   icmp_hun.ih_void
#define icmp_pmvoid icmp_hun.ih_pmtu.ipm_void
#define icmp_nextmtu    icmp_hun.ih_pmtu.ipm_nextmtu
#define icmp_num_addrs  icmp_hun.ih_rtradv.irt_num_addrs
#define icmp_wpa    icmp_hun.ih_rtradv.irt_wpa
#define icmp_lifetime   icmp_hun.ih_rtradv.irt_lifetime
  union
  {
    struct
    {
      u_int32_t its_otime;
      u_int32_t its_rtime;
      u_int32_t its_ttime;
    } id_ts;
    struct
    {
      struct ip_frame idi_ip;
      /* options and then 64 bits of data */
    } id_ip;
    struct icmp_ra_addr id_radv;
    u_int32_t   id_mask;
    u_int8_t    id_data[1];
  } icmp_dun;
#define icmp_otime  icmp_dun.id_ts.its_otime
#define icmp_rtime  icmp_dun.id_ts.its_rtime
#define icmp_ttime  icmp_dun.id_ts.its_ttime
#define icmp_ip     icmp_dun.id_ip.idi_ip
#define icmp_radv   icmp_dun.id_radv
#define icmp_mask   icmp_dun.id_mask
#define icmp_data   icmp_dun.id_data
};

struct dns_query
{
  u_int16_t tid;
  u_int16_t flags;
  u_int16_t questions;
  u_int16_t rrs;  //answer RRs
  u_int16_t arrs; //authority RRs 
  u_int16_t xrrs; //additional RRs
  u_int8_t  qdata;
};

u_int8_t ZERO[32] = {0};

struct dot1x_hdr
{
  u_int8_t  code;
  u_int8_t  idtype;
  u_int16_t length;
}; 

#define DOT1X_CODE_REQ            0x1
#define DOT1X_CODE_RES            0x2
#define DOT1X_CODE_SEC            0x3
#define DOT1X_CODE_FAIL           0x4

#define DOT1X_ID_EAP_PACKET       0x0
#define DOT1X_ID_EAP_START        0x1
#define DOT1X_ID_EAP_LOGOFF       0x2
#define DOT1X_ID_EAP_KEY          0x3

struct radius_hdr
{
  u_int8_t  code;
  u_int8_t  key_mic:1,
            key_secure:1,
            key_error:1,
            key_request:1,
            key_enc:1,
            resv:3;
  u_int8_t  key_ver:3,
            key_type:1,
            key_index:2,
            key_install:1,
            key_ack:1;
  u_int16_t length;
  u_int8_t  replaycnt[8];
  u_int8_t  wpa_nonce[32];
  u_int8_t  wpa_key_iv[16];
  u_int8_t  wpa_key_rsc[8];  
  u_int8_t  wpa_key_id[8];
  u_int8_t  wpa_key_mic[16];
  u_int16_t wpa_key_len;
  u_int8_t  wpa_key_datap; //data starts here
}__attribute__((packed));



#define ETHTYPE_IP                0x08
#define ETHTYPE_8021x             0x8E88
#define PROTO_ICMP                0x01
#define PROTO_TCP                 0x06
#define PROTO_UDP                 0x11

#define CRYPT_NONE 0
#define CRYPT_WEP  1
#define CRYPT_WPA  2

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define PRINTMAC(b) printf("%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n",b[0],b[1],b[2],b[3],b[4],b[5]);

#define DNS_RESP_PCKT "\x6d\x95\x81\x80"\
"\x00\x01"\
"\x00\x01"\
"\x00\x00"\
"\x00\x00"\
"\x03\x77\x77\x77"\
"\x04\x61\x73\x64\x66"\
"\x03\x63\x6f\x6d\x00"\
"\x00\x01"\
"\x00\x01"\
"\xc0\x0c"\
"\x00\x01"\
"\x00\x01"\
"\x00\x00\x14\xb4" \
"\x00\x04"\
"\x45\xa3\xf0\xc0"    

#define DNS_RESP_PCKT_1 \
"\x6d\x95\x81\x80"\
"\x00\x01"\
"\x00\x01"\
"\x00\x00"\
"\x00\x00"

#define DNS_RESP_PCKT_2 \
"\x00\x01"\
"\x00\x01"\
"\xc0\x0c"\
"\x00\x01"\
"\x00\x01"\
"\x00\x00\x14\xb4" \
"\x00\x04"\
"\xC0\xA8\x01\x66"

#define COL_RED        "\e[31m"
#define COL_RED_BOLD   "\e[1;31m"
#define COL_GREEN      "\e[32m"
#define COL_BLUE       "\e[34m"
#define COL_PURPLE     "\e[35m"
#define COL_GRAY       "\e[36m"
#define COL_GRAY_LIGHT "\e[37m"
#define COL_REST       "\e[m"

#define COL_4WAYHS          COL_GRAY
#define COL_4WAYKEY         COL_PURPLE
#define COL_4WAYKEYDATA     COL_GREEN
#define COL_NEWSTA          COL_GREEN
#define COL_NEWSTADATA      COL_GRAY
#define COL_HTTPINJECT      COL_RED
#define COL_HTTPINJECTDATA  COL_RED_BOLD

#define REDIRECT_PLACEHOLDER "https://www.google.com/?gws_rd=ssl"

char *packet302_redirect = "HTTP/1.1 302 Found\r\n\
Location: https://www.google.com/?gws_rd=ssl\r\n\
Cache-Control: private\r\n\
Content-Type: text/html; charset=UTF-8\r\n\
Date: Sun, 30 Nov 2014 03:25:47 GMT\r\n\
Server: gws\r\n\
Content-Length: 231\r\n\
X-XSS-Protection: 1; mode=block\r\n\
X-Frame-Options: SAMEORIGIN\r\n\
Alternate-Protocol: 80:quic,p=0.02\r\n\
\r\n\
<HTML><HEAD><meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\n\
<TITLE>302 Moved</TITLE></HEAD><BODY>\n\
<H1>302 Moved</H1>\n\
The document has moved\n\
<A HREF=\"https://www.google.com/?gws_rd=ssl\">here</A>.\r\n\
</BODY></HTML>\r\n";

