#include <stdint.h>

#define SUCCESS  0
#define FAILURE  1
#define RESTART  2

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define MAX_DICTS 128

#define ASCII_LOW_T 0x21
#define ASCII_HIGH_T 0x7E
#define ASCII_VOTE_STRENGTH_T 150
#define ASCII_DISREGARD_STRENGTH 1

#define TEST_MIN_IVS	4
#define TEST_MAX_IVS	32

#define PTW_TRY_STEP    5000

#define SWAP(x,y) { uchar tmp = x; x = y; y = tmp; }

#define KEYHSBYTES PTW_KEYHSBYTES

#ifdef __i386__

extern int shammx_init( uchar ctx[40] )
__attribute__((regparm(1)));

extern int shammx_ends( uchar ctx[40], uchar digests[40] )
__attribute__((regparm(2)));

extern int shammx_data( uchar ctx[40], uchar data[128], uchar buf[640] )
__attribute__((regparm(3)));
#endif

extern char * getVersion(char * progname, int maj, int min, int submin, int svnrev);
extern int getmac(char * macAddress, int strict, unsigned char * mac);


#define BROADCAST "\xFF\xFF\xFF\xFF\xFF\xFF"
#define SPANTREE  "\x01\x80\xC2\x00\x00\x00"

#define S_LLC_SNAP      "\xAA\xAA\x03\x00\x00\x00"
#define S_LLC_SNAP_ARP  (S_LLC_SNAP "\x08\x06")
#define S_LLC_SNAP_IP   (S_LLC_SNAP "\x08\x00")
#define IEEE80211_FC1_DIR_FROMDS                0x02    /* AP ->STA */
#define KEYLIMIT 1000000

#define N_ATTACKS 17

enum KoreK_attacks
{
	A_u15,						 /* semi-stable  15%             */
	A_s13,						 /* stable       13%             */
	A_u13_1,					 /* unstable     13%             */
	A_u13_2,					 /* unstable ?   13%             */
	A_u13_3,					 /* unstable ?   13%             */
	A_s5_1,						 /* standard      5% (~FMS)      */
	A_s5_2,						 /* other stable  5%             */
	A_s5_3,						 /* other stable  5%             */
	A_u5_1,						 /* unstable      5% no good ?   */
	A_u5_2,						 /* unstable      5%             */
	A_u5_3,						 /* unstable      5% no good     */
	A_u5_4,						 /* unstable      5%             */
	A_s3,						 /* stable        3%             */
	A_4_s13,					 /* stable       13% on q = 4    */
	A_4_u5_1,					 /* unstable      5% on q = 4    */
	A_4_u5_2,					 /* unstable      5% on q = 4    */
	A_neg						 /* helps reject false positives */
};

struct options
{
	int amode;					 /* attack mode          */
	int essid_set;				 /* essid set flag       */
	int bssid_set;				 /* bssid set flag       */
	char essid[33];				 /* target ESSID         */
	uchar bssid[6];				 /* target BSSID         */
	int nbcpu;					 /* # of cracker threads
									(= # of CPU)         */
	int is_quiet;				 /* quiet mode flag      */

	uchar debug[64];			 /* user-defined WEP key */
	int debug_row[64] ;          /* user-defined Row WEP key */
	uchar maddr[6];				 /* MAC address filter   */
	int keylen;					 /* WEP key length       */
	int index;					 /* WEP key index        */
	float ffact;				 /* bruteforce factor    */
	int korek;					 /* attack strategy      */

	int is_fritz;				 /* use numeric keyspace */
	int is_alnum;				 /* alphanum keyspace    */
	int is_bcdonly;				 /* binary coded decimal */

	int do_brute;				 /* bruteforce last 2 KB */
	int do_mt_brute;			 /* bruteforce last 2 KB
									multithreaded for SMP*/
	int do_testy;				 /* experimental attack  */
        int do_ptw;                              /* PTW WEP attack */

	char *dicts[MAX_DICTS];			 /* dictionary files     */
	FILE *dict;				 /* dictionary file      */
	int nbdict;				 /* current dict number  */
	int no_stdin;				 /* if dict == stdin     */
	int hexdict[MAX_DICTS];			 /* if dict in hex       */

	int showASCII;				 /* Show ASCII version of*/
								 /* the wepkey           */

	int l33t;					 /* no comment           */
	int stdin_dict;

	int probability;			/* %of correct answers */
	int votes[N_ATTACKS];			/* votes for korek attacks */
	int brutebytes[64];			/* bytes to bruteforce */
        int next_ptw_try;

	struct AP_info *ap;
}

opt;

typedef struct { int idx, val; }
vote;

struct WEP_data
{
	uchar key[64];				 /* the current chosen WEP key   */
	uchar *ivbuf;				 /* buffer holding all the IVs   */
	int nb_aps;					 /* number of targeted APs       */
	long nb_ivs;				 /* # of unique IVs in buffer    */
	long nb_ivs_now;			 /* # of unique IVs available    */
	int fudge[64];				 /* bruteforce level (1 to 256)  */
	int depth[64];				 /* how deep we are in the fudge */
	vote poll[64][256];			 /* KoreK cryptanalysis results  */
}

wep;

struct WPA_hdsk
{
	uchar stmac[6];				 /* supplicant MAC               */
	uchar snonce[32];			 /* supplicant nonce             */
	uchar anonce[32];			 /* authenticator nonce          */
	uchar keymic[16];			 /* eapol frame MIC              */
	uchar eapol[256];			 /* eapol frame contents         */
	int eapol_size;				 /* eapol frame size             */
	int keyver;					 /* key version (TKIP / AES)     */
	int state;					 /* handshake completion         */
};

struct AP_info
{
	struct AP_info *next;		 /* next AP in linked list       */
	uchar bssid[6];				 /* access point MAC address     */
	char essid[33];				 /* access point identifier      */
	uchar lanip[4];				 /* IP address if unencrypted    */
	uchar *ivbuf;				 /* table holding WEP IV data    */
	uchar **uiv_root;			 /* IV uniqueness root struct    */
	long ivbuf_size;			 /* IV buffer allocated size     */
	long nb_ivs;				 /* total number of unique IVs   */
	int crypt;					 /* encryption algorithm         */
	int eapol;					 /* set if EAPOL is present      */
	int target;					 /* flag set if AP is a target   */
	struct ST_info *st_1st;		 /* linked list of stations      */
	struct WPA_hdsk wpa;		 /* valid WPA handshake data     */
        PTW_attackstate *ptw;
};

struct ST_info
{
	struct AP_info *ap;			 /* parent AP                    */
	struct ST_info *next;		 /* next supplicant              */
	struct WPA_hdsk wpa;		 /* WPA handshake data           */
	unsigned char stmac[6];		 /* client MAC address           */
};

void show_wep_stats( int B, int force, PTW_tableentry table[PTW_KEYHSBYTES][PTW_n], int choices[KEYHSBYTES], int depth[KEYHSBYTES], int prod, int keylimit );
