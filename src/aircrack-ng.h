/*
 *  802.11 WEP / WPA-PSK Key Cracker
 *
 *  Copyright (C) 2007-2012 Martin Beck <hirte@aircrack-ng.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#ifndef _AIRCRACK_NG_H
#define _AIRCRACK_NG_H

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#if defined(__FreeBSD__)
#include <unistd.h>
#endif
#include "aircrack-ptw-lib.h"
#include "eapol.h"

#include <pthread.h>

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

#define KEYHSBYTES PTW_KEYHSBYTES

#define MAX_THREADS 256

#define CLOSE_IT	100000

struct _cpuinfo {
	int simdsize;				/* SIMD size		*/
	char *flags;				/* Feature Flags	*/
	char *model;				/* CPU Model		*/
	int cores;				/* Real CPU cores       */
	int coreperid;				/* Max cores per id     */
	int htt;				/* Hyper-Threading      */
	int maxlogic;				/* Max addressible lCPU */
	int hv;					/* Hypervisor detected  */
	int cpufreq_cur;			/* CPUfreq Current	*/
	int cpufreq_max;			/* CPUfreq Maximum	*/
	float coretemp;				/* CPU Temperature	*/
	char *cputemppath;			/* Linux CPU Sensor Path*/
};

extern float chrono(struct timeval *start, int reset);

extern char * getVersion(char * progname, int maj, int min, int submin, int svnrev, int beta, int rc);
extern int getmac(char * macAddress, int strict, unsigned char * mac);
extern int readLine(char line[], int maxlength);
extern int hexToInt(char s[], int len);
extern int hexCharToInt(unsigned char c);
extern int cpuid_simdsize();
extern int cpuid_getinfo();
extern struct _cpuinfo cpuinfo;
extern int get_nb_cpus();

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

struct dictfiles {
	off_t	dictsize;			/* Total file size */
	off_t	dictpos;			/* Current position of dictionary */
	off_t	wordcount;			/* Total amount of words in dict file */
	int	loaded;				/* Have finished processing? */
} dicts;

struct options
{
	int amode;					 /* attack mode          */
	int essid_set;				 /* essid set flag       */
	int bssid_set;				 /* bssid set flag       */
	char essid[33];				 /* target ESSID         */
	unsigned char bssid[6];				 /* target BSSID         */
	int nbcpu;					 /* # of cracker threads
									(= # of CPU)         */
	int is_quiet;				 /* quiet mode flag      */

	unsigned char debug[64];			 /* user-defined WEP key */
	int debug_row[64] ;          /* user-defined Row WEP key */
	unsigned char maddr[6];				 /* MAC address filter   */
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
	long long int wordcount;		/* Total wordcount for all dicts*/
	struct dictfiles dictidx[MAX_DICTS];	/* Dictionary structure		*/
	int totaldicts;				/* total loaded dictionaries	*/
	int dictfinish;				/* finished processing all dicts*/
	int showASCII;				 /* Show ASCII version of*/
								 /* the wepkey           */

	int l33t;					 /* no comment           */
	int stdin_dict;

	int probability;			/* %of correct answers */
	int votes[N_ATTACKS];			/* votes for korek attacks */
	int brutebytes[64];			/* bytes to bruteforce */
        int next_ptw_try;

	int max_ivs;

	char *bssidmerge;
	unsigned char *firstbssid;
	struct mergeBSSID * bssid_list_1st;

	struct AP_info *ap;

	int wep_decloak;
	int ptw_attack;

	int visual_inspection;       /* Enabling/disabling visual    */
                                 /* inspection of the different  */
                                 /* keybytes                     */

	int oneshot;				 /* Do PTW once */

	char * logKeyToFile;

        int forced_amode;	/* signals disregarding automatic detection of encryption type */

	char * wkp;					 /* EWSA Project file */
	char * hccap;				         /* Hashcat capture file */
	char * hccapx;				/* Hashcat X (3.6+) capture file */
}

opt;

typedef struct { int idx, val; }
vote;

struct WEP_data
{
	unsigned char key[64];				 /* the current chosen WEP key   */
	unsigned char *ivbuf;				 /* buffer holding all the IVs   */
	int nb_aps;					 /* number of targeted APs       */
	long nb_ivs;				 /* # of unique IVs in buffer    */
	long nb_ivs_now;			 /* # of unique IVs available    */
	int fudge[64];				 /* bruteforce level (1 to 256)  */
	int depth[64];				 /* how deep we are in the fudge */
	vote poll[64][256];			 /* KoreK cryptanalysis results  */
} wep __attribute__((aligned(64)));

struct AP_info
{
	struct AP_info *next;		 /* next AP in linked list       */
	unsigned char bssid[6];				 /* access point MAC address     */
	char essid[33];				 /* access point identifier      */
	unsigned char lanip[4];				 /* IP address if unencrypted    */
	unsigned char *ivbuf;				 /* table holding WEP IV data    */
	unsigned char **uiv_root;			 /* IV uniqueness root struct    */
	long ivbuf_size;			 /* IV buffer allocated size     */
	long nb_ivs;				 /* total number of unique IVs   */
	long nb_ivs_clean;			 /* total number of unique IVs   */
	long nb_ivs_vague;				 /* total number of unique IVs   */
	int crypt;					 /* encryption algorithm         */
	int eapol;					 /* set if EAPOL is present      */
	int target;					 /* flag set if AP is a target   */
	struct ST_info *st_1st;		 /* linked list of stations      */
	struct WPA_hdsk wpa;		 /* valid WPA handshake data     */
        PTW_attackstate *ptw_clean;
        PTW_attackstate *ptw_vague;
};

struct ST_info
{
	struct AP_info *ap;			 /* parent AP                    */
	struct ST_info *next;		 /* next supplicant              */
	struct WPA_hdsk wpa;		 /* WPA handshake data           */
	unsigned char stmac[6];		 /* client MAC address           */
};

struct mergeBSSID
{
	unsigned char bssid [6];     /* BSSID */
	char unused[2];				 /* Alignment */
	int convert;				 /* Does this BSSID has to       */
								 /* be converted                 */
	struct mergeBSSID * next;
};


struct WPA_data {
	struct AP_info* ap;				/* AP information */
	int	thread;						/* number of this thread */
	int	threadid;						/* id of this thread */
	int nkeys;						/* buffer capacity */
	char *key_buffer;				/* queue as a circular buffer for feeding and consuming keys */
	int front;						/* front marker for the circular buffers */
	int back;						/* back marker for the circular buffers */
	char key[128];					/* cracked key (0 while not found) */
	pthread_cond_t cond;			/* condition for waiting when buffer is full until keys are tried and new keys can be written */
	pthread_mutex_t mutex;
};


void show_wep_stats( int B, int force, PTW_tableentry table[PTW_KEYHSBYTES][PTW_n], int choices[KEYHSBYTES], int depth[KEYHSBYTES], int prod );

#endif /* _AIRCRACK_NG_H */
