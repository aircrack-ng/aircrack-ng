/*
 *  802.11 WEP / WPA-PSK Key Cracker
 *
 *  Copyright (C) 2006-2022 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
 *  Copyright (C) 2004, 2005 Christophe Devine
 *
 *  Advanced WEP attacks developed by KoreK
 *  WPA-PSK  attack code developed by Joshua Wright
 *  SHA1 MMX assembly code written by Simon Marechal
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
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _GNU_SOURCE

#include <ctype.h>
#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <float.h>
#include <getopt.h>
#include <limits.h>
#include <math.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "aircrack-ng/defs.h"
#include "aircrack-ng/ce-wpa/crypto_engine.h"
#include "aircrack-ng/crypto/sha1-sse2.h"
#include "aircrack-ng/ce-wpa/wpapsk.h"
#include "aircrack-ng/aircrack-ng.h"
#include "aircrack-ng/osdep/byteorder.h"
#include "radiotap/platform.h"
#include "aircrack-ng/adt/avl_tree.h"
#include "aircrack-ng/support/common.h"
#include "aircrack-ng/tui/console.h"
#include "aircrack-ng/cpu/cpuset.h"
#include "aircrack-ng/support/crypto_engine_loader.h"
#include "aircrack-ng/cpu/simd_cpuid.h"
#include "aircrack-ng/cpu/trampoline.h"
#include "aircrack-ng/cowpatty/cowpatty.h"
#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/third-party/hashcat.h"
#include "linecount.h"
#include "aircrack-ng/support/pcap_local.h"
#include "session.h"
#include "aircrack-ng/ce-wep/uniqueiv.h"
#include "aircrack-ng/version.h"
#include "wkp-frame.h"
#include "aircrack-ng/osdep/osdep.h"
#include "aircrack-ng/third-party/ieee80211.h"
#include "aircrack-ng/third-party/ethernet.h"

#ifdef HAVE_SQLITE
#include <sqlite3.h>

static sqlite3 * db = NULL; //-V707
#else
static char * db = NULL; ///-V707
#endif

#ifndef DYNAMIC
#define DYNAMIC 1
#endif

#define MIN_WPA_PASSPHRASE_LEN 2U

#define H16800_PMKID_LEN 32
#define H16800_BSSID_LEN 12
#define H16800_STMAC_LEN 12

#define SECOND_TO_MICROSEC 1e6

/** Maximum duration over all four messages used in EAPOL 802.1x
 *  authentication. Value must be in microseconds.
 */
static const uint64_t eapol_max_fourway_timeout = 5 * SECOND_TO_MICROSEC;
/** Maximum duration between each of the four messages used in
 *  EAPOL 802.1x authentication. Value must be in microseconds.
 */
static const uint64_t eapol_interframe_timeout = SECOND_TO_MICROSEC;
/* stats global data */

static volatile int wpa_cracked = 0;
static int _pmkid_16800 = 0;
static uint8_t _pmkid_16800_str[H16800_PMKID_LEN + H16800_BSSID_LEN
								+ H16800_STMAC_LEN
								+ MAX_PASSPHRASE_LENGTH
								+ 3];
static int _speed_test;
static long _speed_test_length = 15;
static struct timeval t_begin; /* time at start of attack      */
static struct timeval t_stats; /* time since last update       */
static struct timeval t_kprev; /* time at start of window      */
static struct timeval t_dictup; /* next dictionary total read   */
static volatile size_t nb_kprev; /* last  # of keys tried        */
static volatile size_t nb_tried; /* total # of keys tried        */
static ac_crypto_engine_t engine; /* crypto engine */
static int first_wpa_threadid = 0;

/* IPC global data */

static struct options opt;
static struct WEP_data wep __attribute__((aligned(64)));
static c_avl_tree_t * access_points = NULL;
static c_avl_tree_t * targets = NULL;
static pthread_mutex_t mx_apl; /* lock write access to ap LL   */
static pthread_mutex_t mx_eof; /* lock write access to nb_eof  */
static pthread_mutex_t mx_ivb; /* lock access to ivbuf array   */
static pthread_mutex_t mx_dic; /* lock access to opt.dict      */
static pthread_cond_t cv_eof; /* read EOF condition variable  */
static int nb_eof = 0; /* # of threads who reached eof */
static volatile long nb_pkt = 0; /* # of packets read so far     */
static volatile long nb_prev_pkt = 0; /* # of packets read in prior pass */
static int mc_pipe[256][2]; /* master->child control pipe   */
static int cm_pipe[256][2]; /* child->master results pipe   */
static int bf_pipe[256][2]; /* bruteforcer 'queue' pipe	 */
static int bf_nkeys[256];
static unsigned char bf_wepkey[64];
static volatile int wepkey_crack_success = 0;
static volatile int close_aircrack = 0;
static volatile int close_aircrack_fast = 0;
static int id = 0; //-V707
static pthread_t tid[MAX_THREADS] = {0};
static pthread_t cracking_session_tid;
static struct WPA_data wpa_data[MAX_THREADS];
static volatile int wpa_wordlists_done = 0;
static pthread_mutex_t mx_nb = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mx_wpastats = PTHREAD_MUTEX_INITIALIZER;
static ac_cpuset_t * cpuset = NULL;

typedef struct
{
	uint8_t mode;
	char * filename;
} packet_reader_t;

#define PACKET_READER_CHECK_MODE 0
#define PACKET_READER_READ_MODE 1

typedef struct
{
	int tail;
	int off1;
	int off2;
	void * buf1;
	void * buf2;
} read_buf;

static int K_COEFF[N_ATTACKS]
	= {15, 13, 12, 12, 12, 5, 5, 5, 3, 4, 3, 4, 3, 13, 4, 4, -20};

static int PTW_DEFAULTWEIGHT[1] = {256};
static int PTW_DEFAULTBF[PTW_KEYHSBYTES]
	= {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static const unsigned char R[256] = {
	0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,
	15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,
	30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,
	45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,
	60,  61,  62,  63,  64,  65,  66,  67,  68,  69,  70,  71,  72,  73,  74,
	75,  76,  77,  78,  79,  80,  81,  82,  83,  84,  85,  86,  87,  88,  89,
	90,  91,  92,  93,  94,  95,  96,  97,  98,  99,  100, 101, 102, 103, 104,
	105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
	120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
	135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
	150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164,
	165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
	180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194,
	195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
	210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224,
	225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
	240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254,
	255};

static const char usage[]
	= "\n"
	  "  %s - (C) 2006-2022 Thomas d\'Otreppe\n"
	  "  https://www.aircrack-ng.org\n"
	  "\n"
	  "  usage: aircrack-ng [options] <input file(s)>\n"
	  "\n"
	  "  Common options:\n"
	  "\n"
	  "      -a <amode> : force attack mode (1/WEP, 2/WPA-PSK)\n"
	  "      -e <essid> : target selection: network identifier\n"
	  "      -b <bssid> : target selection: access point's MAC\n"
	  "      -p <nbcpu> : # of CPU to use  (default: all CPUs)\n"
	  "      -q         : enable quiet mode (no status output)\n"
	  "      -C <macs>  : merge the given APs to a virtual one\n"
	  "      -l <file>  : write key to file. Overwrites file.\n"
	  "\n"
	  "  Static WEP cracking options:\n"
	  "\n"
	  "      -c         : search alpha-numeric characters only\n"
	  "      -t         : search binary coded decimal chr only\n"
	  "      -h         : search the numeric key for Fritz!BOX\n"
	  "      -d <mask>  : use masking of the key (A1:XX:CF:YY)\n"
	  "      -m <maddr> : MAC address to filter usable packets\n"
	  "      -n <nbits> : WEP key length :  64/128/152/256/512\n"
	  "      -i <index> : WEP key index (1 to 4), default: any\n"
	  "      -f <fudge> : bruteforce fudge factor,  default: 2\n"
	  "      -k <korek> : disable one attack method  (1 to 17)\n"
	  "      -x or -x0  : disable bruteforce for last keybytes\n"
	  "      -x1        : last keybyte bruteforcing  (default)\n"
	  "      -x2        : enable last  2 keybytes bruteforcing"
	  "%s"
	  "      -y         : experimental  single bruteforce mode\n"
	  "      -K         : use only old KoreK attacks (pre-PTW)\n"
	  "      -s         : show the key in ASCII while cracking\n"
	  "      -M <num>   : specify maximum number of IVs to use\n"
	  "      -D         : WEP decloak, skips broken keystreams\n"
	  "      -P <num>   : PTW debug:  1: disable Klein, 2: PTW\n"
	  "      -1         : run only 1 try to crack key with PTW\n"
	  "      -V         : run in visual inspection mode\n"
	  "\n"
	  "  WEP and WPA-PSK cracking options:\n"
	  "\n"
	  "      -w <words> : path to wordlist(s) filename(s)\n"
	  "      -N <file>  : path to new session filename\n"
	  "      -R <file>  : path to existing session filename\n"
	  "\n"
	  "  WPA-PSK options:\n"
	  "\n"
	  "      -E <file>  : create EWSA Project file v3\n"
	  "      -I <str>   : PMKID string (hashcat -m 16800)\n"
	  "      -j <file>  : create Hashcat v3.6+ file (HCCAPX)\n"
	  "      -J <file>  : create Hashcat file (HCCAP)\n"
	  "      -S         : WPA cracking speed test\n"
	  "      -Z <sec>   : WPA cracking speed test length of\n"
	  "                   execution.\n"
#ifdef HAVE_SQLITE
	  "      -r <DB>    : path to airolib-ng database\n"
	  "                   (Cannot be used with -w)\n"
#endif
#if DYNAMIC
	  "\n"
	  "  SIMD selection:\n"
	  "\n"
	  "      --simd-list       : Show a list of the available\n"
	  "                          SIMD architectures, for this\n"
	  "                          machine.\n"
	  "      --simd=<option>   : Use specific SIMD architecture.\n"
	  "\n"
	  "      <option> may be one of the following, depending on\n"
	  "      your platform:\n"
	  "\n"
	  "                   generic\n"
	  "                   avx512\n"
	  "                   avx2\n"
	  "                   avx\n"
	  "                   sse2\n"
	  "                   altivec\n"
	  "                   power8\n"
	  "                   asimd\n"
	  "                   neon\n"
#endif
	  "\n"
	  "  Other options:\n"
	  "\n"
	  "      -u         : Displays # of CPUs & SIMD support\n"
	  "      --help     : Displays this usage screen\n"
	  "\n";

static struct session * cracking_session = NULL;
static char * progname = NULL;

static inline float chrono(struct timeval * start, int reset);
static ssize_t safe_write(int fd, void * buf, size_t len);
static struct AP_info * hccapx_to_ap(struct hccapx * hx);

static inline int append_ap(struct AP_info * new_ap)
{
	REQUIRE(new_ap != NULL);

	return (c_avl_insert(access_points, new_ap->bssid, new_ap));
}

static long load_hccapx_file(int fd)
{
	REQUIRE(fd >= 0);

	hccapx_t hx;
	struct AP_info * ap_cur = NULL;

	lseek(fd, 0, SEEK_SET);

	while (read(fd, &hx, sizeof(hccapx_t)) > 0)
	{
		nb_pkt++;
		ap_cur = hccapx_to_ap(&hx);
		append_ap(ap_cur);
	}

	return (nb_pkt);
}

static struct AP_info * get_first_target(void)
{
	struct AP_info * target = NULL;
	void * key;
	c_avl_iterator_t * it = c_avl_get_iterator(targets);
	c_avl_iterator_next(it, &key, (void **) &target);
	c_avl_iterator_destroy(it);
	return (target);
}

static void destroy_ap(struct AP_info * ap)
{
	REQUIRE(ap != NULL);

	struct ST_info * st_tmp = NULL;

	destroy(ap->ivbuf, free);

	if (ap->stations != NULL)
	{
		void * key = NULL;
		while (c_avl_pick(ap->stations, &key, (void **) &st_tmp) == 0)
		{
			INVARIANT(st_tmp != NULL);

			free(st_tmp);
		}
		c_avl_destroy(ap->stations);
		ap->stations = NULL;
	}

	destroy(ap->uiv_root, uniqueiv_wipe);

	if (ap->ptw_clean)
	{
		destroy(ap->ptw_clean->allsessions, free);
		free(ap->ptw_clean);
	}

	if (ap->ptw_vague)
	{
		destroy(ap->ptw_vague->allsessions, free);
		free(ap->ptw_vague);
	}
}

static void ac_aplist_free(void)
{
	ALLEGE(pthread_mutex_lock(&mx_apl) == 0);

	struct AP_info * ap_cur = NULL;
	void * key;

	while (c_avl_pick(access_points, &key, (void **) &ap_cur) == 0)
	{
		INVARIANT(ap_cur != NULL);

		destroy(ap_cur, destroy_ap);
	}

	ALLEGE(pthread_mutex_unlock(&mx_apl) == 0);
}

/**
 * Release all unused AP base-stations stored in \a access_points, keeping
 * only the specified \a ap_cur AP base-station.
 *
 * @param ap_cur The AP base-station to keep.
 */
static void ap_avl_release_unused(struct AP_info * ap_cur)
{
	REQUIRE(ap_cur != NULL);

	c_avl_tree_t * tmp_access_points = c_avl_create(station_compare);
	c_avl_insert(tmp_access_points, ap_cur->bssid, ap_cur);

	ALLEGE(pthread_mutex_lock(&mx_apl) == 0);

	void * key = NULL;
	struct AP_info * ap_tmp = NULL;
	while (c_avl_pick(access_points, &key, (void **) &ap_tmp) == 0)
	{
		INVARIANT(ap_tmp != NULL);

		if (ap_tmp != ap_cur)
		{
			destroy_ap(ap_tmp);
			free(ap_tmp);
		}
	}

	c_avl_destroy(access_points);
	access_points = tmp_access_points;

	ALLEGE(pthread_mutex_unlock(&mx_apl) == 0);
}

static int
add_wep_iv(struct AP_info * ap, unsigned char * buffer, packet_reader_t * me)
{
	REQUIRE(ap != NULL);
	REQUIRE(buffer != NULL);

	/* check for uniqueness first */
	if (ap->nb_ivs == 0) ap->uiv_root = uniqueiv_init();

	if (uniqueiv_check(ap->uiv_root, buffer) == 0)
	{
		if (me->mode == PACKET_READER_READ_MODE)
		{
			/* add the IV & first two encrypted bytes */

			long n = ap->nb_ivs * 5;

			if (n + 5 > ap->ivbuf_size || ap->ivbuf == NULL)
			{
				/* enlarge the IVs buffer */

				ap->ivbuf_size += 131072;
				uint8_t * tmp_ivbuf
					= realloc(ap->ivbuf, (size_t) ap->ivbuf_size);
				if (tmp_ivbuf == NULL)
				{
					perror("realloc failed");
					return (-1);
				}
				ap->ivbuf = tmp_ivbuf;
			}

			memcpy(ap->ivbuf + n, buffer, 5);
		}

		uniqueiv_mark(ap->uiv_root, buffer);
		ap->nb_ivs++;
	}

	return (0);
}

static int parse_ivs2(struct AP_info * ap_cur,
					  struct ivs2_pkthdr * pivs2,
					  unsigned char * buffer,
					  packet_reader_t * me)
{
	REQUIRE(ap_cur != NULL);
	REQUIRE(pivs2 != NULL);
	REQUIRE(buffer != NULL);

	int weight[16];
	struct ivs2_pkthdr ivs2 = *pivs2;
	long n = 0;

	if (ivs2.flags & IVS2_ESSID)
	{
		memcpy(ap_cur->essid, buffer, ivs2.len);
	}
	else if (ivs2.flags & IVS2_XOR)
	{
		ap_cur->crypt = 2;

		if (opt.do_ptw)
		{
			int clearsize;

			clearsize = ivs2.len;

			if (clearsize < opt.keylen + 3) return (-2);

			if (PTW_addsession(ap_cur->ptw_clean,
							   buffer,
							   buffer + 4,
							   PTW_DEFAULTWEIGHT,
							   1))
				ap_cur->nb_ivs_clean++;

			if (PTW_addsession(ap_cur->ptw_vague,
							   buffer,
							   buffer + 4,
							   PTW_DEFAULTWEIGHT,
							   1))
				ap_cur->nb_ivs_vague++;

			return (-2);
		}

		buffer[3] = buffer[4];
		buffer[4] = buffer[5];
		buffer[3] ^= 0xAA;
		buffer[4] ^= 0xAA;
		/* check for uniqueness first */

		if (ap_cur->nb_ivs == 0) ap_cur->uiv_root = uniqueiv_init();

		if (uniqueiv_check(ap_cur->uiv_root, buffer) == 0)
		{
			if (me->mode == PACKET_READER_READ_MODE)
			{
				/* add the IV & first two encrypted bytes */

				n = ap_cur->nb_ivs * 5;

				if (n + 5 > ap_cur->ivbuf_size)
				{
					/* enlarge the IVs buffer */

					ap_cur->ivbuf_size += 131072;
					uint8_t * tmp_ivbuf
						= realloc(ap_cur->ivbuf, (size_t) ap_cur->ivbuf_size);
					if (tmp_ivbuf == NULL)
					{
						perror("realloc failed");
						return (-1);
					}
					ap_cur->ivbuf = tmp_ivbuf;
				}

				memcpy(ap_cur->ivbuf + n, buffer, 5);
			}
			uniqueiv_mark(ap_cur->uiv_root, buffer);
			ap_cur->nb_ivs++;
		}
	}
	else if (ivs2.flags & IVS2_PTW)
	{
		ap_cur->crypt = 2;

		if (opt.do_ptw)
		{
			int clearsize;

			clearsize = ivs2.len;

			if (buffer[5] < opt.keylen) return (-4);
			if (clearsize < (6 + buffer[4] * 32 + 16 * (signed) sizeof(int)))
				return (-5);

			memcpy(weight,
				   buffer + clearsize - 15 * sizeof(int),
				   16 * sizeof(int));

			ALLEGE(ap_cur->ptw_vague != NULL);

			if (PTW_addsession(
					ap_cur->ptw_vague, buffer, buffer + 6, weight, buffer[4]))
				ap_cur->nb_ivs_vague++;

			return (-6);
		}

		buffer[3] = buffer[6];
		buffer[4] = buffer[7];
		buffer[3] ^= 0xAA;
		buffer[4] ^= 0xAA;
		/* check for uniqueness first */

		if (ap_cur->nb_ivs == 0) ap_cur->uiv_root = uniqueiv_init();

		if (uniqueiv_check(ap_cur->uiv_root, buffer) == 0)
		{
			if (me->mode == PACKET_READER_READ_MODE)
			{
				/* add the IV & first two encrypted bytes */

				n = ap_cur->nb_ivs * 5;

				if (n + 5 > ap_cur->ivbuf_size)
				{
					/* enlarge the IVs buffer */

					ap_cur->ivbuf_size += 131072;
					uint8_t * tmp_ivbuf
						= realloc(ap_cur->ivbuf, (size_t) ap_cur->ivbuf_size);
					if (tmp_ivbuf == NULL)
					{
						perror("realloc failed");
						return (-1);
					}
					ap_cur->ivbuf = tmp_ivbuf;
				}

				memcpy(ap_cur->ivbuf + n, buffer, 5);
			}
			uniqueiv_mark(ap_cur->uiv_root, buffer);
			ap_cur->nb_ivs++;
		}
	}
	else if (ivs2.flags & IVS2_WPA)
	{
		ap_cur->crypt = 3;
		memcpy(&ap_cur->wpa, buffer, sizeof(struct WPA_hdsk));
	}

	return (0);
}

static __attribute__((noinline)) void clean_exit(int ret)
{
	int i = 0;

	char tmpbuf[128];
	memset(tmpbuf, 0, 128);

	close_aircrack = 1;
	if (ret)
	{
		if (!opt.is_quiet)
		{
			printf("\nQuitting aircrack-ng...\n");
			fflush(stdout);
		}

		close_aircrack_fast = 1;

		return;
	}

	if (opt.dict)
	{
		ALLEGE(fclose(opt.dict) == 0);
		ALLEGE(pthread_mutex_lock(&mx_dic) == 0);
		opt.dict = NULL;
		ALLEGE(pthread_mutex_unlock(&mx_dic) == 0);
	}

	for (i = 0; i < opt.nbcpu; i++)
	{
#ifndef CYGWIN
		if (mc_pipe[i][1] != -1)
			safe_write(mc_pipe[i][1], (void *) "EXIT\r", 5);
		if (bf_pipe[i][1] != -1) safe_write(bf_pipe[i][1], (void *) tmpbuf, 64);
#endif
		if (mc_pipe[i][0] != -1) close(mc_pipe[i][0]);
		if (mc_pipe[i][1] != -1) close(mc_pipe[i][1]);
		if (cm_pipe[i][0] != -1) close(cm_pipe[i][0]);
		if (cm_pipe[i][1] != -1) close(cm_pipe[i][1]);
		if (bf_pipe[i][0] != -1) close(bf_pipe[i][0]);
		if (bf_pipe[i][1] != -1) close(bf_pipe[i][1]);

		mc_pipe[i][0] = mc_pipe[i][1] = -1;
		cm_pipe[i][0] = cm_pipe[i][1] = -1;
		bf_pipe[i][0] = bf_pipe[i][1] = -1;
	}

	// Stop cracking session thread
	if (cracking_session)
	{
		ALLEGE(pthread_join(cracking_session_tid, NULL) == 0);
	}

	for (i = 0; i < opt.nbcpu; i++)
		if (tid[i] != 0)
		{
			ALLEGE(pthread_join(tid[i], NULL) == 0);
			tid[i] = 0;
		}

	for (i = 0; i < opt.nbcpu; i++)
	{
		destroy(wpa_data[i].cqueue, circular_queue_free);
		destroy(wpa_data[i].key_buffer, free);
		if (wpa_data[i].thread == i)
		{
			/* ALLEGE(*/ pthread_mutex_destroy(&(wpa_data[i].mutex)) /* == 0)*/;
		}
	}

	ALLEGE(pthread_cond_destroy(&cv_eof) == 0);

	dso_ac_crypto_engine_destroy(&engine);
	ac_crypto_engine_loader_unload();

	if (cpuset != NULL)
	{
		ac_cpuset_destroy(cpuset);
		ac_cpuset_free(cpuset);
	}

	if (opt.totaldicts)
	{
		for (i = 0; i < opt.totaldicts; i++)
		{
			destroy(opt.dicts[i], free);
		}
	}

	destroy(wep.ivbuf, free);

	destroy(opt.logKeyToFile, free);

	ac_aplist_free();

	destroy(access_points, c_avl_destroy);

	destroy(targets, c_avl_destroy);

#ifdef HAVE_SQLITE
	destroy(db, sqlite3_close);
#endif

	destroy(progname, free);

	if (cracking_session)
	{
		// TODO: Delete file when cracking fails
		if (opt.dictfinish || wepkey_crack_success || wpa_wordlists_done
			|| nb_tried == opt.wordcount)
		{
			ac_session_destroy(cracking_session);
		}
		ac_session_free(&cracking_session);
	}

	fflush(stdout);
	fflush(stderr);

	exit(EXIT_SUCCESS);
}

static void sighandler(int signum)
{
#if ((defined(__INTEL_COMPILER) || defined(__ICC)) && defined(DO_PGO_DUMP))
	_PGOPTI_Prof_Dump();
#endif
#if !defined(__CYGWIN__)
	// We can't call this on cygwin or we will sometimes end up
	// having all our threads die with exit code 35584 fairly reproducible
	// at around 2.5-3% of runs
	ALLEGE(signal(signum, sighandler) != SIG_ERR);
#endif

	if (signum == SIGQUIT) clean_exit(EXIT_SUCCESS);

	if (signum == SIGTERM) clean_exit(EXIT_FAILURE);

	if (signum == SIGINT)
	{
#if ((defined(__INTEL_COMPILER) || defined(__ICC)) && defined(DO_PGO_DUMP))
		clean_exit(EXIT_FAILURE);
#else
		clean_exit(EXIT_FAILURE);
#endif
	}

	if (signum == SIGWINCH) erase_display(2);
}

/// Update keys/sec counters with current round of keys.
static inline void
increment_passphrase_counts(wpapsk_password keys[MAX_KEYS_PER_CRYPT_SUPPORTED],
							int nparallel)
{
	int nbkeys = 0;

	for (int i = 0; i < nparallel; i++)
	{
		if (keys[i].length > 0)
		{
			++nbkeys;
		}
	}

	ALLEGE(pthread_mutex_lock(&mx_nb) == 0);

	nb_tried += nbkeys;
	nb_kprev += nbkeys;

	ALLEGE(pthread_mutex_unlock(&mx_nb) == 0);
}

/// Load next wordlist chunk, and count the number of passphrases present.
static inline void wl_count_next_block(struct WPA_data * data)
{
	REQUIRE(data != NULL);

	if (data->thread > 1) return;
	if (opt.dictfinish) return;

	float delta = chrono(&t_dictup, 0);
	if (delta - 2.f >= FLT_EPSILON)
	{
		int i;
		int fincnt = 0;
		size_t tmpword = 0;

		for (i = 0; i < opt.totaldicts; i++)
		{
			if (opt.dictidx[i].loaded)
			{
				fincnt++;
				continue;
			}

			if (opt.dictidx[i].dictsize > READBUF_BLKSIZE)
			{
				if (pthread_mutex_trylock(&mx_dic) == 0)
				{
					tmpword = linecount(opt.dicts[i],
										opt.dictidx[i].dictpos,
										READBUF_MAX_BLOCKS);

					opt.dictidx[i].wordcount += tmpword;
					opt.wordcount += tmpword;
					opt.dictidx[i].dictpos
						+= (READBUF_BLKSIZE * READBUF_MAX_BLOCKS);

					if (opt.dictidx[i].dictpos >= opt.dictidx[i].dictsize)
						opt.dictidx[i].loaded = 1;

					ALLEGE(pthread_mutex_unlock(&mx_dic) == 0);
				}

				// Only process a chunk then come back later for more.
				break;
			}
		}

		if (fincnt == opt.totaldicts)
			opt.dictfinish = 1;
		else
			(void) chrono(&t_dictup, 1);
	}
}

static inline int
wpa_send_passphrase(char * key, struct WPA_data * data, int lock)
{
	REQUIRE(key != NULL);
	REQUIRE(data != NULL);

	if (close_aircrack)
	{
		circular_queue_reset(data->cqueue);
		return (0);
	}

	if (lock)
	{
		circular_queue_push(data->cqueue, key, MAX_PASSPHRASE_LENGTH + 1);
	}
	else
	{
		if (circular_queue_try_push(
				data->cqueue, key, MAX_PASSPHRASE_LENGTH + 1)
			!= 0)
			return (0);
	}

	return (1);
}

static inline int wpa_receive_passphrase(char * key, struct WPA_data * data)
{
	REQUIRE(key != NULL);
	REQUIRE(data != NULL);

	circular_queue_pop(
		data->cqueue, (void * const *) &key, MAX_PASSPHRASE_LENGTH + 1);

	return (1);
}

/* Returns number of BSSIDs.

	Return value is negative for failures
*/
static int checkbssids(const char * bssidlist)
{
	int first = 1;
	int failed = 0;
	int i = 0;
	char *list, *frontlist, *tmp;
	int nbBSSID = 0;

	if (bssidlist == NULL) return (-1);

#define IS_X(x) ((x) == 'X' || (x) == 'x')
#define VALID_CHAR(x) ((IS_X(x)) || hexCharToInt((char) x) > -1)

#define VALID_SEP(arg) (((arg) == '_') || ((arg) == '-') || ((arg) == ':'))
	frontlist = list = strdup(bssidlist);
	do
	{
		tmp = strsep(&list, ",");

		if (tmp == NULL) break;

		++nbBSSID;

		if (strlen(tmp) != 17) failed = 1;

		// first byte
		if (!VALID_CHAR(tmp[0])) failed = 1;
		if (!VALID_CHAR(tmp[1])) failed = 1;
		if (!VALID_SEP(tmp[2])) failed = 1;

		// second byte
		if (!VALID_CHAR(tmp[3])) failed = 1;
		if (!VALID_CHAR(tmp[4])) failed = 1;
		if (!VALID_SEP(tmp[5])) failed = 1;

		// third byte
		if (!VALID_CHAR(tmp[6])) failed = 1;
		if (!VALID_CHAR(tmp[7])) failed = 1;
		if (!VALID_SEP(tmp[8])) failed = 1;

		// fourth byte
		if (!VALID_CHAR(tmp[9])) failed = 1;
		if (!VALID_CHAR(tmp[10])) failed = 1;
		if (!VALID_SEP(tmp[11])) failed = 1;

		// fifth byte
		if (!VALID_CHAR(tmp[12])) failed = 1;
		if (!VALID_CHAR(tmp[13])) failed = 1;
		if (!VALID_SEP(tmp[14])) failed = 1;

		// sixth byte
		if (!VALID_CHAR(tmp[15])) failed = 1;
		if (!VALID_CHAR(tmp[16])) failed = 1;

		if (failed)
		{
			free(frontlist);
			return (-1);
		}

		if (first)
		{
			for (i = 0; i < 17; i++)
			{
				if (IS_X(tmp[i]))
				{
					free(frontlist);
					return (-1);
				}
			}

			opt.firstbssid = (unsigned char *) malloc(sizeof(unsigned char));
			if (opt.firstbssid == NULL)
			{
				free(frontlist);
				return (-1);
			}
			ALLEGE(getmac(tmp, 1, opt.firstbssid) == 0);
			first = 0;
		}

	} while (list);

	// Success
	free(frontlist);
	return (nbBSSID);
}

static THREAD_ENTRY(session_save_thread)
{
	UNUSED_PARAM(arg);

	struct timeval start;
	struct timeval stop;
	int8_t wordlist = 0;
	off_t pos;

	if (!cracking_session || opt.stdin_dict)
	{
		return (NULL);
	}

	// Start chrono
	gettimeofday(&start, NULL);

	while (!close_aircrack)
	{
		// Check if we're over the 10 minutes mark
		gettimeofday(&stop, NULL);
		if (stop.tv_sec - start.tv_sec < 10 * 60)
		{
			// Wait 100ms
			if (usleep(100000) == -1)
			{
				break; // Got a signal
			}
			continue;
		}

		// Reset chrono
		start.tv_sec = stop.tv_sec;

		pos = 0;
		wordlist = 0;

		// Get position in file
		ALLEGE(pthread_mutex_lock(&mx_dic) == 0);
		if (opt.dict)
		{
			wordlist = 1;
			pos = ftello(opt.dict);
		}
		ALLEGE(pthread_mutex_unlock(&mx_dic) == 0);

		// If there is no wordlist, that means it's the end
		// (either forced closing and wordlist was closed or
		//  we've tried all wordlists).
		if (wordlist == 0)
		{
			break;
		}

		// Update amount of keys tried and save it
		ac_session_save(cracking_session, (uint64_t) pos, nb_tried);
	}

	return (NULL);
}

static int mergebssids(const char * bssidlist, unsigned char * bssid)
{
	struct mergeBSSID * list_prev;
	struct mergeBSSID * list_cur;
	char * mac = NULL;
	char * list = NULL;
	char * tmp = NULL;
	char * tmp2 = NULL;
	int next, i, found;

	if (bssid == NULL || bssidlist == NULL || bssidlist[0] == 0)
	{
		return (-1);
	}

	// Do not convert if equal to first bssid
	if (memcmp(opt.firstbssid, bssid, ETHER_ADDR_LEN) == 0) return (1);

	list_prev = NULL;
	list_cur = opt.bssid_list_1st;

	while (list_cur != NULL)
	{
		if (memcmp(list_cur->bssid, bssid, ETHER_ADDR_LEN) == 0)
		{
			if (list_cur->convert)
				memcpy(bssid, opt.firstbssid, ETHER_ADDR_LEN);

			return (list_cur->convert);
		}

		list_prev = list_cur;
		list_cur = list_cur->next;
	}

	// Not found, check if it has to be converted
	mac = (char *) malloc(18);

	if (!mac)
	{
		perror("malloc failed");
		return (-1);
	}

	snprintf(mac,
			 18,
			 "%02X:%02X:%02X:%02X:%02X:%02X",
			 bssid[0],
			 bssid[1],
			 bssid[2],
			 bssid[3],
			 bssid[4],
			 bssid[5]);
	mac[17] = 0;

	tmp2 = list = strdup(bssidlist);
	ALLEGE(tmp2 != NULL);

	// skip first element (because it doesn't have to be converted
	// It already has the good value
	(void) strsep(&list, ",");

	found = 0;

	do
	{
		next = 0;
		tmp = strsep(&list, ",");
		if (tmp == NULL) break;

		// Length already checked, no need to check it again

		for (i = 0; i < 17; ++i)
		{
			if ((IS_X(tmp[i]) || VALID_SEP(tmp[i]))) continue;

			if (toupper((int) tmp[i]) != (int) mac[i])
			{
				// Not found
				next = 1;
				break;
			}
		}

		if (next == 0)
		{
			found = 1;
			break;
		}
	} while (list);

	// Free memory
	free(mac);
	free(tmp2);

	// Add the result to the list
	list_cur = (struct mergeBSSID *) malloc(sizeof(struct mergeBSSID));

	if (!list_cur)
	{
		perror("malloc failed");
		return (-1);
	}

	list_cur->convert = found;
	list_cur->next = NULL;
	memcpy(list_cur->bssid, bssid, ETHER_ADDR_LEN);

	if (opt.bssid_list_1st == NULL)
		opt.bssid_list_1st = list_cur;
	else
		list_prev->next = list_cur;

	// Do not forget to convert if it was successful
	if (list_cur->convert) memcpy(bssid, opt.firstbssid, ETHER_ADDR_LEN);

#undef VALID_CHAR
#undef VALID_SEP
#undef IS_X

	return (list_cur->convert);
}

static ssize_t may_read(int fd)
{
	struct timeval tv;
	fd_set rfds;

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	tv.tv_sec = 0;
	tv.tv_usec = 250000;

	while (select(fd + 1, &rfds, NULL, NULL, &tv) < 0)
	{
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
		if (errno == EBADF) return (0);
		perror("select");
		abort();
	}

	if (FD_ISSET(fd, &rfds))
	{
		return (1);
	}

	return (0);
}

/* fread isn't atomic, sadly */

static int atomic_read(read_buf * rb, int fd, int len, void * buf)
{
	ssize_t n = 0;

	if (close_aircrack) return (0);

	if (rb->buf1 == NULL)
	{
		rb->buf1 = malloc(65536);
		rb->buf2 = malloc(65536);

		if (rb->buf1 == NULL || rb->buf2 == NULL) return (0);

		rb->off1 = 0;
		rb->off2 = 0;
	}

	if (len > 65536 - rb->off1)
	{
		rb->off2 -= rb->off1;

		memcpy(rb->buf2, (char *) rb->buf1 + rb->off1, (size_t) rb->off2);
		memcpy(rb->buf1, (char *) rb->buf2, (size_t) rb->off2);

		rb->off1 = 0;
	}

	if (rb->off2 - rb->off1 >= len)
	{
		memcpy(buf, (char *) rb->buf1 + rb->off1, (size_t) len);
		rb->off1 += len;
		return (1);
	}
	else
	{
	tail_until_close:
		do
		{
			if (may_read(fd))
			{
				n = read(fd,
						 (char *) rb->buf1 + rb->off2,
						 (size_t)(65536 - rb->off2));
			}

			if (close_aircrack) return (0);
		} while (rb->tail && n == 0);

		if (n <= 0) return (0);

		rb->off2 += n;

		if (rb->off2 - rb->off1 >= len)
		{
			memcpy(buf, (char *) rb->buf1 + rb->off1, (size_t) len);
			rb->off1 += len;
			return (1);
		}
		else
		{
			if (rb->tail) goto tail_until_close;
		}
	}

	return (0);
}

/**
 * Calculate the WEP session's keystream, for PTW based attacks.
 *
 * @param body The packet data contained within an 802.11 frame.
 * @param dlen The length of the \a body parameter.
 * @param ap_cur A reference to the AP base-station.
 * @param h80211 A reference to the entire 802.11 frame data, for
 *               which \a body is located inside.
 * @return Returns zero on success. Returns non-zero for an error (> zero)
 *         or exception (< zero).
 */
static int calculate_wep_keystream(unsigned char * body,
								   int dlen,
								   struct AP_info * ap_cur,
								   unsigned char * h80211)
{
	REQUIRE(body != NULL);
	REQUIRE(ap_cur != NULL);
	REQUIRE(h80211 != NULL);

	unsigned char clear[2048];
	int clearsize, i, j, k;
	int weight[16];

	memset(weight, 0, sizeof(weight));
	memset(clear, 0, sizeof(clear));

	/* calculate keystream */
	k = known_clear(clear, &clearsize, weight, h80211, (size_t) dlen);
	if (clearsize < (opt.keylen + 3)) return (0);

	for (j = 0; j < k; j++)
	{
		for (i = 0; i < clearsize; i++) clear[i + (32 * j)] ^= body[4 + i];
	}

	if (k == 1)
	{
		if (ap_cur->ptw_clean == NULL)
		{
			ap_cur->ptw_clean = PTW_newattackstate();
			if (!ap_cur->ptw_clean)
			{
				perror("PTW_newattackstate()");
				return (-1);
			}
		}

		if (PTW_addsession(ap_cur->ptw_clean, body, clear, weight, k))
			ap_cur->nb_ivs_clean++;
	}

	if (ap_cur->ptw_vague == NULL)
	{
		ap_cur->ptw_vague = PTW_newattackstate();
		if (!ap_cur->ptw_vague)
		{
			perror("PTW_newattackstate()");
			return (-2);
		}
	}

	if (PTW_addsession(ap_cur->ptw_vague, body, clear, weight, k))
		ap_cur->nb_ivs_vague++;

	return (0);
}

/**
 * Updates the current AP with additional information, such as stations.
 *
 * @param ap_cur The AP we are updating.
 * @param fmt The incoming \a buffer binary format.
 * @param buffer The incoming packet data.
 * @param h80211 A reference within \a buffer for the 802.11 frame.
 * @param ivs2 A reference to an IVS2 packet structure.
 * @param pkh A reference to the packet's header content.
 * @return Returns zero on success. Returns non-zero for an error (> zero)
 *         or exception (< zero).
 */
static int packet_reader__update_ap_info(struct AP_info * ap_cur,
										 int fmt,
										 unsigned char * buffer,
										 unsigned char * h80211,
										 struct ivs2_pkthdr * ivs2,
										 struct pcap_pkthdr * pkh,
										 packet_reader_t * me)
{
	REQUIRE(ap_cur != NULL);
	REQUIRE(buffer != NULL);
	REQUIRE(h80211 != NULL);
	REQUIRE(ivs2 != NULL);
	REQUIRE(pkh != NULL);

	struct ST_info * st_cur = NULL;
	unsigned char stmac[ETHER_ADDR_LEN];
	unsigned char * p = NULL;

	if (fmt == FORMAT_IVS)
	{
		ap_cur->crypt = 2;
		add_wep_iv(ap_cur, buffer, me);
		return (0);
	}
	else if (fmt == FORMAT_IVS2)
	{
		parse_ivs2(ap_cur, ivs2, buffer, me);
		return (0);
	}

	/* locate the station MAC in the 802.11 header */

	switch (h80211[1] & IEEE80211_FC1_DIR_MASK)
	{
		case IEEE80211_FC1_DIR_NODS:
		case IEEE80211_FC1_DIR_TODS:
			memcpy(stmac, h80211 + 10, ETHER_ADDR_LEN);
			break;

		case IEEE80211_FC1_DIR_FROMDS:
			/* reject broadcast MACs */
			if ((h80211[4] % 2) != 0) goto skip_station;
			memcpy(stmac, h80211 + 4, ETHER_ADDR_LEN);
			break;

		default:
			goto skip_station;
	}

	int not_found = c_avl_get(ap_cur->stations, stmac, (void **) &st_cur);

	/* if it's a new supplicant, add it */
	if (not_found)
	{
		st_cur = (struct ST_info *) malloc(sizeof(struct ST_info));
		if (st_cur == NULL)
		{
			perror("malloc failed");
			return (-1);
		}
		memset(st_cur, 0, sizeof(struct ST_info));

		memcpy(st_cur->stmac, stmac, sizeof(st_cur->stmac));
		c_avl_insert(ap_cur->stations, st_cur->stmac, st_cur);
	}

skip_station:

	/* packet parsing: Beacon or Probe Response */

	if (h80211[0] == IEEE80211_FC0_SUBTYPE_BEACON
		|| h80211[0] == IEEE80211_FC0_SUBTYPE_PROBE_RESP)
	{
		if (ap_cur->crypt == 0) ap_cur->crypt = (h80211[34] & 0x10u) >> 4u;

		p = h80211 + 36;

		while (p < h80211 + pkh->caplen)
		{
			if (p + 2 + p[1] > h80211 + pkh->caplen) break;

			if (p[0] == 0x00 && p[1] > 0 && p[2] != '\0')
			{
				/* found a non-cloaked ESSID */
				size_t n = (p[1] > 32) ? 32 : p[1];

				memset(ap_cur->essid, 0, ESSID_LENGTH + 1);
				memcpy(ap_cur->essid, p + 2, n);
			}

			p += 2 + p[1];
		}
	}

	/* packet parsing: Association Request */

	if (h80211[0] == IEEE80211_FC0_SUBTYPE_ASSOC_REQ)
	{
		p = h80211 + 28;

		while (p < h80211 + pkh->caplen)
		{
			if (p + 2 + p[1] > h80211 + pkh->caplen) break;

			if (p[0] == 0x00 && p[1] > 0 && p[2] != '\0')
			{
				size_t n = (p[1] > 32) ? 32 : p[1];

				memset(ap_cur->essid, 0, ESSID_LENGTH + 1);
				memcpy(ap_cur->essid, p + 2, n);
			}

			p += 2 + p[1];
		}
	}

	/* packet parsing: Association Response */

	if (h80211[0] == IEEE80211_FC0_SUBTYPE_ASSOC_RESP)
	{
		/* reset the WPA handshake state */
		if (st_cur != NULL) st_cur->wpa.state = 0;
	}

	/* check if data */

	if ((h80211[0] & IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_DATA)
		return (0);

	/* check minimum size */

	unsigned z
		= ((h80211[1] & IEEE80211_FC1_DIR_MASK) != IEEE80211_FC1_DIR_DSTODS)
			  ? 24
			  : 30;
	if ((h80211[0] & IEEE80211_FC0_SUBTYPE_BEACON)
		== IEEE80211_FC0_SUBTYPE_BEACON)
		z += 2; /* 802.11e QoS */

	if (z + 16 > pkh->caplen) return (0);

	/* check the SNAP header to see if data is encrypted */

	if (h80211[z] != h80211[z + 1] || h80211[z + 2] != 0x03)
	{
		if (!opt.forced_amode)
		{
			ap_cur->crypt = 2; /* encryption = WEP */

			/* check the extended IV flag */
			if ((h80211[z + 3] & 0x20) != 0)
			{
				/* encryption = WPA */
				ap_cur->crypt = 3;
			}
		}

		/* check the WEP key index */

		if (opt.index != 0 && (h80211[z + 3] >> 6) != opt.index - 1) return (0);

		if (opt.do_ptw)
		{
			unsigned char * body = h80211 + z;
			int data_len = (int) (pkh->caplen - (body - h80211) - 4 - 4);

			if ((h80211[1] & IEEE80211_FC1_DIR_MASK)
				== IEEE80211_FC1_DIR_DSTODS) // 30byte header
			{
				body += 6;
				data_len -= 6;
			}

			calculate_wep_keystream(body, data_len, ap_cur, h80211);

			return (0);
		}

		/* save the IV & first two output bytes */

		memcpy(buffer, h80211 + z, 3);
		memcpy(buffer + 3, h80211 + z + 4, 2);

		/* Special handling for spanning-tree packets */
		if (memcmp(h80211 + 4, SPANTREE, ETHER_ADDR_LEN) == 0
			|| memcmp(h80211 + 16, SPANTREE, ETHER_ADDR_LEN) == 0)
		{
			buffer[3] = (uint8_t)((buffer[3] ^ 0x42) ^ 0xAA);
			buffer[4] = (uint8_t)((buffer[4] ^ 0x42) ^ 0xAA);
		}

		add_wep_iv(ap_cur, buffer, me);

		return (0);
	}

	/* if ethertype == IPv4, find the LAN address */

	z += 6;

	if (z + 20 < pkh->caplen)
	{
		if (h80211[z] == 0x08 && h80211[z + 1] == 0x00
			&& (h80211[1] & 3) == 0x01)
			memcpy(ap_cur->lanip, &h80211[z + 14], 4);

		if (h80211[z] == 0x08 && h80211[z + 1] == 0x06)
			memcpy(ap_cur->lanip, &h80211[z + 16], 4);
	}

	/* check ethertype == EAPOL */

	if (h80211[z] != 0x88 || h80211[z + 1] != 0x8E) return (0);

	z += 2;

	ap_cur->eapol = 1;

	/* type == 3 (key), desc. == 254 (WPA) or 2 (RSN) */

	if (h80211[z + 1] != 0x03
		|| (h80211[z + 4] != 0xFE && h80211[z + 4] != 0x02))
		return (0);

	ap_cur->eapol = 0;
	if (!opt.forced_amode) ap_cur->crypt = 3; /* set WPA */

	if (st_cur == NULL)
	{
		// NOTE: no station present; so we want to SKIP this AP.
		return (1);
	}

	const uint64_t now_us = pkh->tv_sec * SECOND_TO_MICROSEC + pkh->tv_usec;
	const uint64_t replay_counter
		= be64_to_cpu(get_unaligned((uint64_t *) (&h80211[z + 9])));

	if (st_cur->wpa.timestamp_start_us > 0
		&& subs_u64(now_us, st_cur->wpa.timestamp_start_us)
			   > eapol_max_fourway_timeout)
	{
		fprintf(stderr, "Resetting EAPOL Handshake decoder state.\n");
		memset(&st_cur->wpa, 0, sizeof(struct WPA_hdsk));
	}

	/* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */

	if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) == 0
		&& (h80211[z + 6] & 0x80) != 0
		&& (h80211[z + 5] & 0x01) == 0)
	{
		if (st_cur->wpa.timestamp_start_us == 0)
		{
			st_cur->wpa.timestamp_start_us = now_us;
			st_cur->wpa.timestamp_last_us = now_us;
		}
		if (subs_u64(now_us, st_cur->wpa.timestamp_last_us)
			> eapol_interframe_timeout)
		{
			// exceeds the inter-frame timeout period
			memset(&st_cur->wpa, 0, sizeof(struct WPA_hdsk));
			st_cur->wpa.timestamp_start_us = now_us;
		}
		// update last recv time.
		st_cur->wpa.timestamp_last_us = now_us;

		/* authenticator nonce set */
		st_cur->wpa.state = 1;
		memcpy(st_cur->wpa.anonce, &h80211[z + 17], sizeof(st_cur->wpa.anonce));

		st_cur->wpa.found |= 1 << 1;

		st_cur->wpa.replay = replay_counter;

		if (h80211[z + 99] == IEEE80211_ELEMID_VENDOR)
		{
			const uint8_t rsn_oui[] = {
				RSN_OUI & 0xff, (RSN_OUI >> 8) & 0xff, (RSN_OUI >> 16) & 0xff};

			if (memcmp(rsn_oui, &h80211[z + 101], 3) == 0
				&& h80211[z + 104] == RSN_CSE_CCMP)
			{
				if (memcmp(ZERO, &h80211[z + 105], 16) != 0) //-V512
				{
					// Got a PMKID value?!
					memcpy(st_cur->wpa.pmkid, &h80211[z + 105], 16);

					/* copy the key descriptor version */
					st_cur->wpa.keyver = (uint8_t)(h80211[z + 6] & 7);
				}
			}
		}
	}

	/* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */

	if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) == 0
		&& (h80211[z + 6] & 0x80) == 0
		&& (h80211[z + 5] & 0x01) != 0)
	{
		if (st_cur->wpa.timestamp_start_us == 0)
		{
			st_cur->wpa.timestamp_start_us = now_us;
			st_cur->wpa.timestamp_last_us = now_us;
		}
		INVARIANT(now_us > 0);
		INVARIANT(st_cur->wpa.timestamp_start_us != 0);
		INVARIANT(st_cur->wpa.timestamp_last_us != 0);
		if (subs_u64(now_us, st_cur->wpa.timestamp_last_us)
			> eapol_interframe_timeout)
		{
			// exceeds the inter-frame timeout period
			st_cur->wpa.found &= ~((1 << 4) | (1 << 2)); // unset M2 and M4
			fprintf(stderr, "Inter-frame timeout period exceeded.\n");
			return (1);
		}
		// update last recv time.
		st_cur->wpa.timestamp_last_us = now_us;

		if (st_cur->wpa.state == 0)
		{
			// no M1; so we store the M2 replay counter.
			st_cur->wpa.replay = replay_counter;
		}
		else if (st_cur->wpa.replay != replay_counter)
		{
			// Bad replay counter value in message M2 or M4.
			return (1);
		}

		if (memcmp(&h80211[z + 17], ZERO, sizeof(st_cur->wpa.snonce)) != 0)
		{
			memcpy(st_cur->wpa.snonce,
				   &h80211[z + 17],
				   sizeof(st_cur->wpa.snonce));

			/* supplicant nonce set */
			st_cur->wpa.state |= 2;
		}

		// uint16_t key_len = ((h80211[z + 7] << 8u) + h80211[z + 8]);
		uint16_t key_data_len
			= (h80211[z + 81 + 16] << 8u) + h80211[z + 81 + 17];

		if (key_data_len == 0)
		{
			st_cur->wpa.found |= 1 << 4; // frame 4
		}
		else
		{
			st_cur->wpa.found |= 1 << 2; // frame 2
		}

		if ((st_cur->wpa.state & 4) != 4)
		{
			/* copy the MIC & eapol frame */
			st_cur->wpa.eapol_size
				= (uint32_t)((h80211[z + 2] << 8) + h80211[z + 3] + 4);

			if (st_cur->wpa.eapol_size == 0 //-V560
				|| st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol)
				|| pkh->len - z < st_cur->wpa.eapol_size)
			{
				// Ignore the packet trying to crash us.
				st_cur->wpa.eapol_size = 0;

				return (0);
			}

			memcpy(st_cur->wpa.keymic, &h80211[z + 81], 16);
			memcpy(st_cur->wpa.eapol, &h80211[z], st_cur->wpa.eapol_size);
			memset(st_cur->wpa.eapol + 81, 0, 16);

			if (key_data_len == 0)
			{
				st_cur->wpa.eapol_source |= 1 << 4; // frame 4
			}
			else
			{
				st_cur->wpa.eapol_source |= 1 << 2; // frame 2
			}

			/* eapol frame & keymic set */
			st_cur->wpa.state |= 4;

			/* copy the key descriptor version */
			st_cur->wpa.keyver = (uint8_t)(h80211[z + 6] & 7);
		}
	}

	/* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */
	/* M3's replay counter MUST be larger than M1/M2's. */

	if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) != 0
		&& (h80211[z + 6] & 0x80) != 0
		&& (h80211[z + 5] & 0x01) != 0
		&& st_cur->wpa.replay < replay_counter)
	{
		if (st_cur->wpa.timestamp_start_us == 0)
		{
			st_cur->wpa.timestamp_start_us = now_us;
			st_cur->wpa.timestamp_last_us = now_us;
		}
		INVARIANT(st_cur->wpa.timestamp_last_us != 0);
		if (subs_u64(now_us, st_cur->wpa.timestamp_last_us)
			> eapol_interframe_timeout)
		{
			// exceeds the inter-frame timeout period
			st_cur->wpa.found &= ~(1 << 3); // unset M3
			fprintf(stderr, "Inter-frame timeout period exceeded.\n");
			return (1);
		}
		// update last recv time.
		st_cur->wpa.timestamp_last_us = now_us;

		st_cur->wpa.found |= 1 << 3;
		// Store M3 for comparison with M4.
		st_cur->wpa.replay = replay_counter;

		if (memcmp(&h80211[z + 17], ZERO, sizeof(st_cur->wpa.anonce)) != 0)
		{
			memcpy(st_cur->wpa.anonce,
				   &h80211[z + 17],
				   sizeof(st_cur->wpa.anonce));

			/* authenticator nonce set */
			st_cur->wpa.state |= 1;
		}

		if ((st_cur->wpa.state & 4) != 4)
		{
			/* copy the MIC & eapol frame */
			st_cur->wpa.eapol_size
				= (uint32_t)((h80211[z + 2] << 8) + h80211[z + 3] + 4);

			if (st_cur->wpa.eapol_size == 0 //-V560
				|| st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol)
				|| pkh->len - z < st_cur->wpa.eapol_size)
			{
				// Ignore the packet trying to crash us.
				st_cur->wpa.eapol_size = 0;

				return (0);
			}

			memcpy(st_cur->wpa.keymic, &h80211[z + 81], 16);
			memcpy(st_cur->wpa.eapol, &h80211[z], st_cur->wpa.eapol_size);
			memset(st_cur->wpa.eapol + 81, 0, 16);

			st_cur->wpa.eapol_source |= 1 << 3;

			/* eapol frame & keymic set */
			st_cur->wpa.state |= 4;

			/* copy the key descriptor version */
			st_cur->wpa.keyver = (uint8_t)(h80211[z + 6] & 7);
		}
	}

	// The new PMKID attack permits any state greater than 0, with a PMKID
	// present.
	if (st_cur->wpa.state == 7
		|| (st_cur->wpa.state > 0 && st_cur->wpa.pmkid[0] != 0x00))
	{
		/* got one valid handshake */
		memcpy(st_cur->wpa.stmac, stmac, ETHER_ADDR_LEN);
		memcpy(&ap_cur->wpa, &st_cur->wpa, sizeof(struct WPA_hdsk));
	}

	return (0);
}

/**
 * Process a single packet, to extract useful access point data.
 *
 * @param me A reference to our own (this ptr) data.
 * @param bssid The base station MAC address.
 * @param dest An extra base station MAC address. ?
 * @param fmt The incoming packet \a buffer binary format.
 * @param buffer The incoming packet data.
 * @param h80211 A reference within \a buffer for the 802.11 frame.
 * @param ivs2 A reference to an IVS2 packet structure.
 * @param pkh A reference to the packet's header content.
 * @param ap_cur An output parameter to hold a found, or updated, AP base
 *               station.
 * @return Returns zero on success. Returns non-zero for an error (> zero)
 *         or exception (< zero).
 */
static int packet_reader_process_packet(packet_reader_t * me,
										uint8_t * bssid,
										uint8_t * dest,
										int fmt,
										unsigned char * buffer,
										unsigned char * h80211,
										struct ivs2_pkthdr * ivs2,
										struct pcap_pkthdr * pkh,
										struct AP_info ** ap_cur)
{
	REQUIRE(me != NULL);
	REQUIRE(bssid != NULL);
	REQUIRE(dest != NULL);
	REQUIRE(buffer != NULL);
	REQUIRE(h80211 != NULL);
	REQUIRE(ivs2 != NULL);
	REQUIRE(pkh != NULL);
	REQUIRE(ap_cur != NULL);

	*ap_cur = NULL;

	nb_pkt++;

	if (fmt == FORMAT_CAP)
	{
		/* skip packets smaller than a 802.11 header */

		if (pkh->caplen < 24) return (0);

		/* skip (uninteresting) control frames */

		if ((h80211[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_CTL)
			return (0);

		/* locate the access point's MAC address */

		switch (h80211[1] & IEEE80211_FC1_DIR_MASK)
		{
			case IEEE80211_FC1_DIR_NODS:
				memcpy(bssid, h80211 + 16, ETHER_ADDR_LEN); //-V525
				break; // Adhoc
			case IEEE80211_FC1_DIR_TODS:
				memcpy(bssid, h80211 + 4, ETHER_ADDR_LEN);
				break; // ToDS
			case IEEE80211_FC1_DIR_FROMDS:
			case IEEE80211_FC1_DIR_DSTODS:
				memcpy(bssid, h80211 + 10, ETHER_ADDR_LEN);
				break; // WDS -> Transmitter taken as BSSID
			default:
				fprintf(stderr,
						"Expected a value between 0 and 3, got %d.\n",
						h80211[1] & IEEE80211_FC1_DIR_MASK);
				break;
		}

		switch (h80211[1] & IEEE80211_FC1_DIR_MASK)
		{
			case IEEE80211_FC1_DIR_NODS:
			case IEEE80211_FC1_DIR_FROMDS:
				memcpy(dest, h80211 + 4, ETHER_ADDR_LEN);
				break; // Adhoc
			case IEEE80211_FC1_DIR_TODS:
			case IEEE80211_FC1_DIR_DSTODS:
				memcpy(dest, h80211 + 16, ETHER_ADDR_LEN);
				break; // WDS -> Transmitter taken as BSSID
			default:
				fprintf(stderr,
						"Expected a value between 0 and 3, got %d.\n",
						h80211[1] & IEEE80211_FC1_DIR_MASK);
				break;
		}

		// skip corrupted keystreams in wep decloak mode
		if (opt.wep_decloak)
		{
			if (dest[0] == 0x01) return (0);
		}
	}

	if (opt.bssidmerge) mergebssids(opt.bssidmerge, bssid);

	if (memcmp(bssid, BROADCAST, ETHER_ADDR_LEN) == 0)
		/* probe request or such - skip the packet */
		return (0);

	if (me->mode == PACKET_READER_READ_MODE)
	{
		if (memcmp(bssid, opt.bssid, ETHER_ADDR_LEN) != 0) return (0);
	}

	if (memcmp(opt.maddr, ZERO, ETHER_ADDR_LEN) != 0
		&& memcmp(opt.maddr, BROADCAST, ETHER_ADDR_LEN) != 0)
	{
		/* apply the MAC filter */
		if (memcmp(opt.maddr, h80211 + 4, ETHER_ADDR_LEN) != 0
			&& memcmp(opt.maddr, h80211 + 10, ETHER_ADDR_LEN) != 0
			&& memcmp(opt.maddr, h80211 + 16, ETHER_ADDR_LEN) != 0)
			return (0);
	}

	/* search for the station */

	int not_found = c_avl_get(access_points, bssid, (void **) ap_cur);

	/* if it's a new access point, add it */
	if (not_found)
	{
		if (!(*ap_cur = (struct AP_info *) malloc(sizeof(struct AP_info))))
		{
			perror("malloc failed");
			return (-1);
		}

		memset((*ap_cur), 0, sizeof(struct AP_info));
		memcpy((*ap_cur)->bssid, bssid, ETHER_ADDR_LEN);

		(*ap_cur)->crypt = -1;

		// Shortcut to set encryption:
		// - WEP is 2 for 'crypt' and 1 for 'amode'.
		// - WPA is 3 for 'crypt' and 2 for 'amode'.
		if (opt.forced_amode) (*ap_cur)->crypt = opt.amode + 1;

		if (opt.do_ptw == 1)
		{
			(*ap_cur)->ptw_clean = PTW_newattackstate();
			if (!(*ap_cur)->ptw_clean)
			{
				perror("PTW_newattackstate()");
				free(*ap_cur);
				*ap_cur = NULL;
				return (-1);
			}

			(*ap_cur)->ptw_vague = PTW_newattackstate();
			if (!(*ap_cur)->ptw_vague)
			{
				perror("PTW_newattackstate()");
				free(*ap_cur);
				*ap_cur = NULL;
				return (-1);
			}
		}
		(*ap_cur)->stations = c_avl_create(station_compare);
		append_ap(*ap_cur);
	}

	int rv = packet_reader__update_ap_info(
		*ap_cur, fmt, buffer, h80211, ivs2, pkh, me);
	if (rv != 0)
	{
		if (rv > 0)
		{
			// NOTE: skipping this AP base station.
			*ap_cur = NULL;
			return (1);
		}
		else
		{
			// NOTE: an error occurred.
			return (rv);
		}
	}

	return (0);
}

/**
 * Thread controlling the processing of packet data from a file or stream.
 *
 * This thread is called in one of two possible ways:
 *
 * a. With a BSSID specified from the command-line parameters.
 *
 * b. Without a BSSID specified in the command-line parameters.
 *
 * The goal of both is, to read one or more AP base-stations from the packet
 * capture files given (passed inside of \a arg); producing our needed
 * structures for later cracking.
 *
 * When a BSSID is specified, we ONLY read data relating to that BSSID. This
 * mode is called PACKET_READER_READ_MODE.
 *
 * Otherwise, the entire file is loaded in to RAM. This mode is called
 * PACKET_READER_CHECK_MODE.
 *
 * **NOTE**: This thread is joinable, and MUST be joined after use.
 *
 * @param arg A heap allocated, filled in \a packet_reader_t structure.
 *            We handle releasing the memory upon function exit.
 */
static THREAD_ENTRY(packet_reader_thread)
{
	REQUIRE(arg != NULL);

	packet_reader_t * request = (packet_reader_t *) arg;
	unsigned char * buffer = NULL;
	read_buf rb = {0};

	int fd = -1;
	int n;
	int fmt;

	unsigned char bssid[ETHER_ADDR_LEN] = {0};
	unsigned char dest[ETHER_ADDR_LEN] = {0};
	unsigned char * h80211 = NULL;

	struct ivs2_pkthdr ivs2 = {0};
	struct ivs2_filehdr fivs2 = {0};
	struct pcap_pkthdr pkh = {0};
	struct pcap_file_header pfh = {0};
	struct AP_info * ap_cur = NULL;

	REQUIRE(request->filename != NULL);
	REQUIRE((request->mode == PACKET_READER_CHECK_MODE)
			|| (request->mode == PACKET_READER_READ_MODE));

	ALLEGE(signal(SIGINT, sighandler) != SIG_ERR);

	rb.tail = (request->mode == PACKET_READER_CHECK_MODE
			   || (request->mode == PACKET_READER_READ_MODE //-V560
				   && (opt.essid_set || opt.bssid_set)))
				  ? 0
				  : 1;

	if ((buffer = (unsigned char *) malloc(65536)) == NULL)
	{
		/* there is no buffer */
		perror("malloc failed");
		goto read_fail;
	}

	h80211 = buffer;

	if (!opt.is_quiet) printf("Opening %s\n", request->filename);

	if (strcmp(request->filename, "-") == 0)
		fd = 0;
	else
	{
		if ((fd = open(request->filename, O_RDONLY | O_BINARY)) < 0)
		{
			fprintf(stderr,
					"Failed to open '%s' (%d): %s\n",
					request->filename,
					errno,
					strerror(errno));
			goto read_fail;
		}
	}

	if (!atomic_read(&rb, fd, 4, &pfh))
	{
		perror("read(file header) failed");
		goto read_fail;
	}

	fmt = FORMAT_IVS;
	if (memcmp(&pfh, HCCAPX_MAGIC, 4) == 0
		|| memcmp(&pfh, HCCAPX_CIGAM, 4) == 0)
	{
		fmt = FORMAT_HCCAPX;
	}
	else if (memcmp(&pfh, IVSONLY_MAGIC, 4) != 0
			 && memcmp(&pfh, IVS2_MAGIC, 4) != 0)
	{
		fmt = FORMAT_CAP;

		if (pfh.magic != TCPDUMP_MAGIC && pfh.magic != TCPDUMP_CIGAM)
		{
			fprintf(stderr,
					"Unsupported file format "
					"(not a pcap or IVs file).\n");
			goto read_fail;
		}

		/* read the rest of the pcap file header */

		if (!atomic_read(&rb, fd, 20, (unsigned char *) &pfh + 4))
		{
			perror("read(file header) failed");
			goto read_fail;
		}

		/* take care of endian issues and check the link type */

		if (pfh.magic == TCPDUMP_CIGAM)
		{
			pfh.version_major = ___my_swab16(pfh.version_major);
			pfh.version_minor = ___my_swab16(pfh.version_minor);
			pfh.snaplen = ___my_swab32(pfh.snaplen);
			pfh.linktype = ___my_swab32(pfh.linktype);
		}

		if (pfh.linktype != LINKTYPE_IEEE802_11
			&& pfh.linktype != LINKTYPE_PRISM_HEADER
			&& pfh.linktype != LINKTYPE_RADIOTAP_HDR
			&& pfh.linktype != LINKTYPE_PPI_HDR)
		{
			fprintf(stderr,
					"This file is not a regular "
					"802.11 (wireless) capture.\n");
			goto read_fail;
		}
	}
	else
	{
		if (opt.wep_decloak)
		{
			fprintf(stderr, "Can't use decloak wep mode with ivs\n");
			goto read_fail;
		}

		if (memcmp(&pfh, IVS2_MAGIC, 4) == 0)
		{
			fmt = FORMAT_IVS2;

			if (!atomic_read(&rb,
							 fd,
							 sizeof(struct ivs2_filehdr),
							 (unsigned char *) &fivs2))
			{
				perror("read(file header) failed");
				goto read_fail;
			}

			if (fivs2.version > IVS2_VERSION)
			{
				fprintf(stderr,
						"Error, wrong %s version: %d. Supported up to version "
						"%d.\n",
						IVS2_EXTENSION,
						fivs2.version,
						IVS2_VERSION);
				goto read_fail;
			}
		}
		else if (opt.do_ptw)
		{
			fprintf(stderr,
					"Can't do PTW with old IVS files, recapture without --ivs "
					"or use airodump-ng >= 1.0\n");
			goto read_fail;
		}
	}

	while (1)
	{
		if (close_aircrack) break;

		if (fmt == FORMAT_IVS)
		{
			/* read one IV */
			if (!atomic_read(&rb, fd, 1, buffer)) goto done_reading;

			if (close_aircrack) break;

			if (buffer[0] != 0xFF)
			{
				/* new access point MAC */
				bssid[0] = buffer[0];

				if (!atomic_read(&rb, fd, 5, bssid + 1)) goto done_reading;
			}

			if (!atomic_read(&rb, fd, 5, buffer)) goto done_reading;
		}
		else if (fmt == FORMAT_IVS2)
		{
			if (!atomic_read(&rb, fd, sizeof(struct ivs2_pkthdr), &ivs2))
				goto done_reading;

			if (ivs2.flags & IVS2_BSSID)
			{
				if (!atomic_read(&rb, fd, ETHER_ADDR_LEN, bssid))
					goto done_reading;

				ivs2.len -= ETHER_ADDR_LEN;
			}

			if (!atomic_read(&rb, fd, ivs2.len, buffer)) goto done_reading;
		}
		else if (fmt == FORMAT_HCCAPX)
		{
			load_hccapx_file(fd);
			goto done_reading;
		}
		else
		{
			if (!atomic_read(&rb, fd, sizeof(pkh), &pkh)) goto done_reading;

			if (pfh.magic == TCPDUMP_CIGAM)
			{
				pkh.caplen = ___my_swab32(pkh.caplen);
				pkh.len = ___my_swab32(pkh.len);
			}

			if (pkh.caplen <= 0 || pkh.caplen > 65535)
			{
				fprintf(stderr,
						"\nInvalid packet capture length %lu - "
						"corrupted file?\n",
						(unsigned long) pkh.caplen);
				goto done_reading;
			}

			if (!atomic_read(&rb, fd, pkh.caplen, buffer)) goto done_reading;

			h80211 = buffer;

			if (pfh.linktype == LINKTYPE_PRISM_HEADER)
			{
				/* remove the prism header */
				if (h80211[7] == 0x40)
					n = 64;
				else
				{
					n = load32_le(h80211 + 4);
				}

				if (n < 8 || n >= (int) pkh.caplen) continue;

				h80211 += n;
				pkh.caplen -= n;
			}

			else if (pfh.linktype == LINKTYPE_RADIOTAP_HDR)
			{
				/* remove the radiotap header */
				n = load16_le(h80211 + 2);

				if (n <= 0 || n >= (int) pkh.caplen) continue;

				h80211 += n;
				pkh.caplen -= n;
			}

			else if (pfh.linktype == LINKTYPE_PPI_HDR)
			{
				/* Remove the PPI header */
				n = load16_le(h80211 + 2);

				if (n <= 0 || n >= (int) pkh.caplen) continue;

				/* for a while Kismet logged broken PPI headers */
				if (n == 24 && load16_le(h80211 + 8) == 2) n = 32;

				h80211 += n;
				pkh.caplen -= n;
			}
			else if (pfh.linktype == LINKTYPE_IEEE802_11)
			{
				/* nothing to do */
			}
			else
			{
				fprintf(stderr, "unsupported linktype %u\n", pfh.linktype);
				continue;
			}
		}

		ALLEGE(pthread_mutex_lock(&mx_apl) == 0);

		int rv = packet_reader_process_packet(
			request, bssid, dest, fmt, buffer, h80211, &ivs2, &pkh, &ap_cur);

		ALLEGE(pthread_mutex_unlock(&mx_apl) == 0);

		if (rv < 0)
		{
			// NOTE: An error occurred during processing, bail!
			goto done_reading;
		}

		if (ap_cur != NULL)
		{
			if ((ap_cur->nb_ivs >= opt.max_ivs)
				|| (ap_cur->nb_ivs_clean >= opt.max_ivs)
				|| (ap_cur->nb_ivs_vague >= opt.max_ivs))
			{
				goto done_reading;
			}
		}

		if (request->mode == PACKET_READER_READ_MODE && nb_prev_pkt == nb_pkt)
		{
			ALLEGE(pthread_mutex_lock(&mx_eof) == 0);
			pthread_cond_signal(&cv_eof);
			ALLEGE(pthread_mutex_unlock(&mx_eof) == 0);
		}
	}

done_reading:
	++nb_eof;

read_fail:
	ALLEGE(pthread_mutex_lock(&mx_eof) == 0);
	pthread_cond_signal(&cv_eof);
	ALLEGE(pthread_mutex_unlock(&mx_eof) == 0);

	destroy(buffer, free);
	destroy(rb.buf1, free);
	destroy(rb.buf2, free);

	if (fd != -1) close(fd);

	free(arg);

	return (NULL);
}

/* timing routine */

static __attribute__((always_inline)) float chrono(struct timeval * start,
												   int reset)
{
	REQUIRE(start != NULL);

	float delta;
	struct timeval current;

	gettimeofday(&current, NULL);

	delta = (current.tv_sec - start->tv_sec)
			+ (float) (current.tv_usec - start->tv_usec) / 1000000.f;

	if (reset) gettimeofday(start, NULL);

	return (delta);
}

/* signal-safe I/O routines */

static ssize_t safe_read(int fd, void * buf, size_t len)
{
	REQUIRE(buf != NULL);
	REQUIRE(len > 0);
	if (fd < 0) return (-1);

	ssize_t n;
	size_t sum = 0;
	char * off = (char *) buf;

	while (sum < len)
	{
		n = 0;

		if (may_read(fd))
		{
			if (!(n = read(fd, (void *) off, len - sum)))
			{
				return (0);
			}
		}
		if (close_aircrack) return (-1);

		if (n < 0 && errno == EINTR) continue;
		if (n < 0) return (n);

		sum += n;
		off += n;
	}

	return (sum);
}

static ssize_t safe_write(int fd, void * buf, size_t len)
{
	REQUIRE(buf != NULL);
	REQUIRE(len > 0);
	if (fd < 0) return (-1);

	ssize_t n;
	size_t sum = 0;
	char * off = (char *) buf;

	while (sum < len)
	{
		if ((n = write(fd, (void *) off, len - sum)) < 0)
		{
			if (errno == EINTR) continue;
			return (n);
		}

		sum += n;
		off += n;
	}

	return (sum);
}

/* each thread computes the votes over a subset of the IVs */

static THREAD_ENTRY(crack_wep_thread)
{
	long xv, min, max;
	unsigned char jj[256] = {0};
	unsigned char S[256], Si[256];
	unsigned char K[64];

	unsigned char io1, o1, io2, o2;
	unsigned char Sq, dq, Kq, jq, q;
	unsigned char S1, S2, J2, t2;

	int i, j, B = 0, cid = (int) ((long) arg);
	int votes[N_ATTACKS][256];
	int first = 1, first2, oldB = 0, oldq = 0;

	memcpy(S, R, 256);
	memcpy(Si, R, 256);

	while (1)
	{
		if (safe_read(mc_pipe[cid][0], (void *) &B, sizeof(int)) != sizeof(int))
		{
			return ((void *) FAILURE); //-V566
		}
		if (close_aircrack) break;

		first2 = 1;

		min = 5 * (((cid) *wep.nb_ivs) / opt.nbcpu);
		max = 5 * (((1 + cid) * wep.nb_ivs) / opt.nbcpu);

		q = (uint8_t)(3 + B);

		if (B > 0 && (size_t) B < sizeof(wep.key) - 3)
			memcpy(K + 3, wep.key, (size_t) B);
		memset(votes, 0, sizeof(votes));

		/* START: KoreK attacks */

		for (xv = min; xv < max; xv += 5)
		{
			if (!first)
			{
				for (i = 0; i < oldq; i++)
				{
					S[i] = Si[i] = (uint8_t) i;
					S[jj[i]] = Si[jj[i]] = jj[i];
				}
			}

			ALLEGE(pthread_mutex_lock(&mx_ivb) == 0);

			memcpy(K, &wep.ivbuf[xv], 3); //-V512

			INVARIANT((size_t) q < sizeof(K));
			for (i = j = 0; i < q; i++)
			{
				INVARIANT((size_t) i < sizeof(K));
				INVARIANT((size_t) i < sizeof(S));

				jj[i] = (uint8_t)((j + S[i] + K[i]) & 0xFF);
				j = (j + S[i] + K[i]) & 0xFF;
				SWAP(S[i], S[j]);
			}

			i = q;
			do
			{
				i--;
				SWAP(Si[i], Si[jj[i]]);
			} while (i != 0);

			o1 = (uint8_t)(wep.ivbuf[xv + 3] ^ 0xAA);
			io1 = Si[o1];
			S1 = S[1];
			o2 = (uint8_t)(wep.ivbuf[xv + 4] ^ 0xAA);
			io2 = Si[o2];
			S2 = S[2];

			ALLEGE(pthread_mutex_unlock(&mx_ivb) == 0);

			if (first) first = 0;
			if (first2)
			{
				oldB = B;
				oldq = 3 + oldB;
				first2 = 0;
			}

			Sq = S[q];
			dq = Sq + jj[q - 1];

			if (S2 == 0)
			{
				if ((S1 == 2) && (o1 == 2))
				{
					Kq = (uint8_t) 1 - dq;
					votes[A_neg][Kq]++;
					Kq = (uint8_t) 2 - dq;
					votes[A_neg][Kq]++;
				}
				else if (o2 == 0)
				{
					Kq = (uint8_t) 2 - dq;
					votes[A_neg][Kq]++;
				}
			}
			else
			{
				if ((o2 == 0) && (Sq == 0))
				{
					Kq = (uint8_t) 2 - dq;
					votes[A_u15][Kq]++;
				}
			}

			if ((S1 == 1) && (o1 == S2))
			{
				Kq = (uint8_t) 1 - dq;
				votes[A_neg][Kq]++;
				Kq = (uint8_t) 2 - dq;
				votes[A_neg][Kq]++;
			}

			if ((S1 == 0) && (S[0] == 1) && (o1 == 1))
			{
				Kq = (uint8_t) 0 - dq;
				votes[A_neg][Kq]++;
				Kq = (uint8_t) 1 - dq;
				votes[A_neg][Kq]++;
			}

			if (S1 == q)
			{
				if (o1 == q)
				{
					Kq = Si[0] - dq;
					votes[A_s13][Kq]++;
				}
				else if (((1 - q - o1) & 0xFF) == 0)
				{
					Kq = io1 - dq;
					votes[A_u13_1][Kq]++;
				}
				else if (io1 < q)
				{
					jq = Si[(io1 - q) & 0xFF];

					if (jq != 1)
					{
						Kq = jq - dq;
						votes[A_u5_1][Kq]++;
					}
				}
			}

			if ((io1 == 2) && (S[q] == 1))
			{
				Kq = (uint8_t) 1 - dq;
				votes[A_u5_2][Kq]++;
			}

			if (S[q] == q)
			{
				if ((S1 == 0) && (o1 == q))
				{
					Kq = (uint8_t) 1 - dq;
					votes[A_u13_2][Kq]++;
				}
				else if ((((1 - q - S1) & 0xFF) == 0) && (o1 == S1))
				{
					Kq = (uint8_t) 1 - dq;
					votes[A_u13_3][Kq]++;
				}
				else if ((S1 >= ((-q) & 0xFF))
						 && (((q + S1 - io1) & 0xFF) == 0))
				{
					Kq = (uint8_t) 1 - dq;
					votes[A_u5_3][Kq]++;
				}
			}

			if ((S1 < q) && (((S1 + S[S1] - q) & 0xFF) == 0) && (io1 != 1)
				&& (io1 != S[S1]))
			{
				Kq = io1 - dq;
				votes[A_s5_1][Kq]++;
			}

			if ((S1 > q) && (((S2 + S1 - q) & 0xFF) == 0))
			{
				if (o2 == S1)
				{
					jq = Si[(S1 - S2) & 0xFF];

					if ((jq != 1) && (jq != 2))
					{
						Kq = jq - dq;
						votes[A_s5_2][Kq]++;
					}
				}
				else if (o2 == ((2 - S2) & 0xFF))
				{
					jq = io2;

					if ((jq != 1) && (jq != 2))
					{
						Kq = jq - dq;
						votes[A_s5_3][Kq]++;
					}
				}
			}

			if ((S[1] != 2) && (S[2] != 0))
			{
				J2 = S[1] + S[2];

				if (J2 < q)
				{
					t2 = S[J2] + S[2];

					if ((t2 == q) && (io2 != 1) && (io2 != 2) && (io2 != J2))
					{
						Kq = io2 - dq;
						votes[A_s3][Kq]++;
					}
				}
			}

			if (S1 == 2)
			{
				if (q == 4)
				{
					if (o2 == 0)
					{
						Kq = Si[0] - dq;
						votes[A_4_s13][Kq]++;
					}
					else
					{
						if ((jj[1] == 2) && (io2 == 0))
						{
							Kq = Si[254] - dq;
							votes[A_4_u5_1][Kq]++;
						}
						if ((jj[1] == 2) && (io2 == 2))
						{
							Kq = Si[255] - dq;
							votes[A_4_u5_2][Kq]++;
						}
					}
				}
				else if ((q > 4) && ((S[4] + 2) == q) && (io2 != 1)
						 && (io2 != 4))
				{
					Kq = io2 - dq;
					votes[A_u5_4][Kq]++;
				}
			}
			if (close_aircrack) break;
		}
		if (close_aircrack) break;
		/* END: KoreK attacks */

		if (safe_write(cm_pipe[cid][1], votes, sizeof(votes)) != sizeof(votes))
		{
			perror("write failed");
			kill(0, SIGTERM);
			_exit(EXIT_FAILURE);
		}
	}

	return ((void *) SUCCESS);
}

/* display the current votes */

void show_wep_stats(int B,
					int force,
					PTW_tableentry table[PTW_KEYHSBYTES][PTW_n],
					int choices[KEYHSBYTES],
					int depth[KEYHSBYTES],
					int prod)
{
	float delta;
	struct winsize ws;
	int i, et_h, et_m, et_s;
	static int is_cleared = 0;

	if ((chrono(&t_stats, 0) < 1.51 || wepkey_crack_success) && force == 0)
		return;

	if (ioctl(0, TIOCGWINSZ, &ws) < 0)
	{
		ws.ws_row = 25;
		ws.ws_col = 80;
	}

	chrono(&t_stats, 1);

	delta = chrono(&t_begin, 0);

	et_h = (int) (delta / 3600);
	et_m = (int) ((delta - et_h * 3600) / 60);
	et_s = (int) (delta - et_h * 3600 - et_m * 60);

	if (is_cleared == 0)
	{
		is_cleared++;

		if (opt.l33t) textcolor_bg(TEXT_BLACK);

		erase_display(2);
	}

	if (opt.l33t) textcolor(TEXT_BRIGHT, TEXT_BLUE, TEXT_BLACK);

	moveto((ws.ws_col - (int) strlen(progname)) / 2, 2);
	printf("%s\n\n", progname);

	if (opt.l33t) textcolor(TEXT_BRIGHT, TEXT_YELLOW, TEXT_BLACK);

	moveto((ws.ws_col - 44) / 2, 5);
	if (table)
		printf("[%02d:%02d:%02d] Tested %d keys (got %ld IVs)",
			   et_h,
			   et_m,
			   et_s,
			   prod,
			   opt.ap->nb_ivs);
	else
		printf("[%02d:%02d:%02d] Tested %zd keys (got %ld IVs)",
			   et_h,
			   et_m,
			   et_s,
			   nb_tried,
			   wep.nb_ivs_now);
	erase_line(0);

	if (opt.l33t)
	{
		textcolor_fg(TEXT_GREEN);
		textcolor_normal();
	}

	moveto(4, 7);
	printf("KB    depth   byte(vote)\n");

	for (i = 0; i <= B; i++)
	{
		int j, k = (ws.ws_col - 20) / 11;

		if (!table)
		{
			if (opt.l33t)
			{
				printf("   %2d  ", i);
				textstyle(TEXT_BRIGHT);
				printf("%3d", wep.depth[i]);
				textcolor_fg(TEXT_GREEN);
				printf("/%3d   ", wep.fudge[i]);
			}
			else
				printf("   %2d  %3d/%3d   ", i, wep.depth[i], wep.fudge[i]);
		}
		else
			printf("   %2d  %3d/%3d   ", i, depth[i], choices[i]);

		if (table)
		{
			for (j = depth[i]; j < k + depth[i]; j++)
			{
				if (j >= 256) break;

				if (opt.l33t)
				{
					textstyle(TEXT_BRIGHT);
					printf("%02X", table[i][j].b);
					textcolor_fg(TEXT_GREEN);
					printf("(%4d) ", table[i][j].votes);
				}
				else
					printf("%02X(%4d) ", table[i][j].b, table[i][j].votes);
			}
		}
		else
		{
			for (j = wep.depth[i]; j < k + wep.depth[i]; j++)
			{
				if (j >= 256) break;

				if (wep.poll[i][j].val == 32767)
				{
					if (opt.l33t)
					{
						textstyle(TEXT_BRIGHT);
						printf("%02X", wep.poll[i][j].idx);
						textcolor_normal();
						printf("(+inf) ");
					}
					else
						printf("%02X(+inf) ", wep.poll[i][j].idx);
				}
				else
				{
					if (opt.l33t)
					{
						textstyle(TEXT_BRIGHT);
						printf("%02X", wep.poll[i][j].idx);
						textcolor_normal();
						printf("(%4d) ", wep.poll[i][j].val);
					}
					else
						printf("%02X(%4d) ",
							   wep.poll[i][j].idx,
							   wep.poll[i][j].val);
				}
			}
		}
		if (opt.showASCII && !table)
			if (wep.poll[i][wep.depth[i]].idx >= ASCII_LOW_T
				&& wep.poll[i][wep.depth[i]].idx <= ASCII_HIGH_T)
				if (wep.poll[i][wep.depth[i]].val >= ASCII_VOTE_STRENGTH_T
					|| ASCII_DISREGARD_STRENGTH) //-V560
					printf("  %c", wep.poll[i][wep.depth[i]].idx);

		printf("\n");
	}

	if (B < opt.keylen - 1) erase_display(0);

	printf("\n");
}

static void key_found(unsigned char * wepkey, int keylen, int B)
{
	REQUIRE(wepkey != NULL);
	REQUIRE(keylen >= 0);

	FILE * keyFile;
	int i, n;
	int nb_ascii = 0;

	if (opt.probability < 1) return;

	for (i = 0; i < keylen; i++)
		if (wepkey[i] == 0 || (wepkey[i] >= 32 && wepkey[i] < 127)) nb_ascii++;

	wepkey_crack_success = 1;
	memcpy(bf_wepkey, wepkey, (size_t) keylen);

	if (opt.is_quiet)
		printf("KEY FOUND! [ ");
	else
	{
		if (B != -1) show_wep_stats(B - 1, 1, NULL, NULL, NULL, 0);

		if (opt.l33t)
		{
			textstyle(TEXT_BRIGHT);
			textcolor_fg(TEXT_RED);
		}

		n = (80 - 14 - keylen * 3) / 2;

		if (100 * nb_ascii > 75 * keylen) n -= (keylen + 4) / 2;

		if (n <= 0) n = 0;

		erase_line(0);
		move(CURSOR_FORWARD, n);
		printf("KEY FOUND! [ ");
	}

	for (i = 0; i < keylen - 1; i++) printf("%02X:", wepkey[i]);
	printf("%02X ] ", wepkey[i]);

	if (nb_ascii == keylen)
	{
		printf("(ASCII: ");

		for (i = 0; i < keylen; i++)
			printf("%c",
				   ((wepkey[i] > 31 && wepkey[i] < 127) || wepkey[i] > 160)
					   ? wepkey[i]
					   : '.');

		printf(" )");
	}

	if (opt.l33t)
	{
		textcolor_fg(TEXT_GREEN);
		textcolor_normal();
	}

	printf("\n\tDecrypted correctly: %d%%\n", opt.probability);
	printf("\n");

	// Write the key to a file
	if (opt.logKeyToFile != NULL)
	{
		keyFile = fopen(opt.logKeyToFile, "w");
		if (keyFile != NULL)
		{
			for (i = 0; i < keylen; i++) fprintf(keyFile, "%02X", wepkey[i]);
			fclose(keyFile);
		}
	}
}

/* test if the current WEP key is valid */

static int check_wep_key(unsigned char * wepkey, int B, int keylen)
{
	unsigned char x1, x2;
	unsigned long xv;
	size_t i, j, n, bad;
	unsigned long tests;

	unsigned char K[64];
	unsigned char S[256];

	if (keylen <= 0) keylen = opt.keylen;

	ALLEGE(pthread_mutex_lock(&mx_nb) == 0);
	nb_tried++;
	ALLEGE(pthread_mutex_unlock(&mx_nb) == 0);

	bad = 0;

	memcpy(K + 3, wepkey, (size_t) keylen);

	tests = 32;

	if (opt.dict) tests = (unsigned long) wep.nb_ivs;

	if (tests < TEST_MIN_IVS) tests = TEST_MIN_IVS;
	if (tests > TEST_MAX_IVS) tests = TEST_MAX_IVS;

	for (n = 0; n < tests; n++)
	{
		xv = 5u * n;

		ALLEGE(pthread_mutex_lock(&mx_ivb) == 0);

		memcpy(K, &wep.ivbuf[xv], 3); //-V512
		memcpy(S, R, sizeof(S));

		for (i = j = 0; i < 256; i++)
		{
			j = (j + S[i] + K[i % (3 + keylen)]) & 0xFF;
			SWAP(S[i], S[j]);
		}

		i = 1;
		j = (size_t)((0 + S[i]) & 0xFF);
		SWAP(S[i], S[j]);
		x1 = wep.ivbuf[xv + 3] ^ S[(S[i] + S[j]) & 0xFF];

		i = 2;
		j = (size_t)((j + S[i]) & 0xFF);
		SWAP(S[i], S[j]);
		x2 = wep.ivbuf[xv + 4] ^ S[(S[i] + S[j]) & 0xFF];

		ALLEGE(pthread_mutex_unlock(&mx_ivb) == 0);

		if ((x1 != 0xAA || x2 != 0xAA) && (x1 != 0xE0 || x2 != 0xE0)
			&& (x1 != 0x42 || x2 != 0x42)
			&& (x1 != 0x02 || x2 != 0xAA)) // llc sub layer management
			bad++;

		if (bad > ((tests * opt.probability) / 100)) return (FAILURE);
	}

	opt.probability = (int) (((tests - bad) * 100) / tests);
	key_found(wepkey, keylen, B);

	return (SUCCESS);
}

/* sum up the votes and sort them */

static int calc_poll(int B)
{
	int i, cid, *vi;
	size_t n;
	int votes[N_ATTACKS][256];

	memset(&opt.votes, '\0', sizeof(opt.votes));

	/* send the current keybyte # to each thread */

	for (cid = 0; cid < opt.nbcpu; cid++)
	{
		n = sizeof(int);

		if ((size_t) safe_write(mc_pipe[cid][1], &B, n) != n)
		{
			perror("write failed");
			kill(0, SIGTERM);
			_exit(EXIT_FAILURE);
		}
	}

	/* collect the votes, multiply by the korek coeffs */

	for (i = 0; i < 256; i++)
	{
		wep.poll[B][i].idx = i;
		wep.poll[B][i].val = 0;
	}

	for (cid = 0; cid < opt.nbcpu; cid++)
	{
		n = sizeof(votes);

		if ((size_t) safe_read(cm_pipe[cid][0], votes, n) != n)
		{
			return (FAILURE);
		}

		for (n = 0, vi = (int *) votes; n < N_ATTACKS; n++)
			for (i = 0; i < 256; i++, vi++)
			{
				wep.poll[B][i].val += *vi * K_COEFF[n];
				if (K_COEFF[n]) opt.votes[n] += *vi;
			}
	}

	/* set votes to the max if the keybyte is user-defined */

	if (opt.debug_row[B]) wep.poll[B][opt.debug[B]].val = 32767;

	/* if option is set, restrict keyspace to alpha-numeric */

	if (opt.is_alnum)
	{
		for (i = 1; i < 32; i++) wep.poll[B][i].val = -1;

		for (i = 127; i < 256; i++) wep.poll[B][i].val = -1;
	}

	if (opt.is_fritz)
	{
		for (i = 0; i < 48; i++) wep.poll[B][i].val = -1;

		for (i = 58; i < 256; i++) wep.poll[B][i].val = -1;
	}

	/* if option is set, restrict keyspace to BCD hex digits */

	if (opt.is_bcdonly)
	{
		for (i = 1; i < 256; i++)
			if (i > 0x99 || (i & 0x0F) > 0x09) wep.poll[B][i].val = -1;
	}

	/* sort the votes, highest ones first */

	qsort(wep.poll[B], 256, sizeof(vote), cmp_votes);

	return (SUCCESS);
}

static int update_ivbuf(void)
{
	size_t n;
	struct AP_info * ap_cur;
	void * key;

	/* 1st pass: compute the total number of available IVs */

	wep.nb_ivs_now = 0;
	wep.nb_aps = 0;
	c_avl_iterator_t * it = c_avl_get_iterator(access_points);

	while (c_avl_iterator_next(it, &key, (void **) &ap_cur) == 0)
	{
		if (ap_cur->crypt == 2 && ap_cur->target)
		{
			wep.nb_ivs_now += ap_cur->nb_ivs;
			wep.nb_aps++;
		}
	}
	c_avl_iterator_destroy(it);

	/* 2nd pass: create the main IVs buffer if necessary */

	if (wep.nb_ivs == 0
		|| (opt.keylen == 5 && wep.nb_ivs_now - wep.nb_ivs > 20000)
		|| (opt.keylen >= 13 && wep.nb_ivs_now - wep.nb_ivs > 40000))
	{
		/* one buffer to rule them all */

		ALLEGE(pthread_mutex_lock(&mx_ivb) == 0);

		destroy(wep.ivbuf, free);

		wep.nb_ivs = 0;

		it = c_avl_get_iterator(access_points);
		while (c_avl_iterator_next(it, &key, (void **) &ap_cur) == 0)
		{
			if (ap_cur->ivbuf != NULL && ap_cur->crypt == 2 && ap_cur->target)
			{
				n = (size_t) ap_cur->nb_ivs;

				uint8_t * tmp_ivbuf = realloc(wep.ivbuf, (wep.nb_ivs + n) * 5u);
				if (tmp_ivbuf == NULL)
				{
					ALLEGE(pthread_mutex_unlock(&mx_ivb) == 0);
					perror("realloc failed");
					kill(0, SIGTERM);
					_exit(EXIT_FAILURE);
				}
				wep.ivbuf = tmp_ivbuf;

				memcpy(wep.ivbuf + wep.nb_ivs * 5u, ap_cur->ivbuf, 5u * n);

				wep.nb_ivs += n;
			}
		}
		c_avl_iterator_destroy(it);

		ALLEGE(pthread_mutex_unlock(&mx_ivb) == 0);

		return (RESTART);
	}

	return (SUCCESS);
}

/*
 * It will remove votes for a specific keybyte (and remove from the requested
 * current value)
 * Return 0 on success, another value on failure
 */
static int remove_votes(int keybyte, unsigned char value)
{
	int i;
	int found = 0;

	for (i = 0; i < 256; i++)
	{
		if (wep.poll[keybyte][i].idx == (int) value)
		{
			found = 1;
		}

		if (found)
		{
			// Put the value at the end with NO votes
			if (i == 255)
			{
				wep.poll[keybyte][i].idx = (int) value;
				wep.poll[keybyte][i].val = 0;
			}
			else
			{
				wep.poll[keybyte][i].idx = wep.poll[keybyte][i + 1].idx;
				wep.poll[keybyte][i].val = wep.poll[keybyte][i + 1].val;
				if (i == 0)
				{
					// Also update wep key if it's the first value to remove
					wep.key[keybyte] = (uint8_t) wep.poll[keybyte][i].idx;
				}
			}
		}
	}

	return (0);
}

/* standard attack mode: */
/* this routine gathers and sorts the votes, then recurses until it *
 * reaches B == keylen. It also stops when the current keybyte vote *
 * is lower than the highest vote divided by the fudge factor.      */

static int do_wep_crack1(int B)
{
	int i, j, l, m, tsel, charread;
	int remove_keybyte_nr, remove_keybyte_value;
	static int k = 0;
	char user_guess[4];

get_ivs:
	if (wepkey_crack_success) return (SUCCESS);

	switch (update_ivbuf())
	{
		case FAILURE:
			return (FAILURE);
		case RESTART:
			return (RESTART);
		default:
			break;
	}

	if ((wep.nb_ivs_now < 256 && opt.debug[0] == 0)
		|| (wep.nb_ivs_now < 32 && opt.debug[0] != 0))
	{
		if (!opt.no_stdin)
		{
			printf("Not enough IVs available. You need about 250 000 IVs to "
				   "crack\n"
				   "40-bit WEP, and more than 800 000 IVs to crack a 104-bit "
				   "key.\n");
			kill(0, SIGTERM);
			_exit(EXIT_FAILURE);
		}
		else
		{
			printf(
				"Read %ld packets, got %ld IVs...\n", nb_pkt, wep.nb_ivs_now);
			fflush(stdout);

			sleep(1);
			goto get_ivs;
		}
	}

	/* if last keybyte reached, check if the key is valid */

	if (B == opt.keylen)
	{
		if (!opt.is_quiet) show_wep_stats(B - 1, 0, NULL, NULL, NULL, 0);

		return (check_wep_key(wep.key, B, 0));
	}

	/* now compute the poll results for keybyte B */

	if (calc_poll(B) != SUCCESS) return (FAILURE);

	/* fudge threshold = highest vote divided by fudge factor */

	for (wep.fudge[B] = 1; wep.fudge[B] < 256; wep.fudge[B]++)
		if ((float) wep.poll[B][wep.fudge[B]].val
			< (float) wep.poll[B][0].val / opt.ffact)
			break;

	/* try the most likely n votes, where n is the fudge threshold */

	for (wep.depth[B] = 0;
		 wep.fudge[B] > 0 && wep.fudge[B] < 256 && wep.depth[B] < wep.fudge[B];
		 wep.depth[B]++)
	{
		switch (update_ivbuf())
		{
			case FAILURE:
				return (FAILURE);
			case RESTART:
				return (RESTART);
			default:
				break;
		}

		wep.key[B] = (uint8_t) wep.poll[B][wep.depth[B]].idx;

		if (!opt.is_quiet)
		{
			show_wep_stats(B, 0, NULL, NULL, NULL, 0);
		}

		if (B == 4 && opt.keylen == 13)
		{
			/* even when cracking 104-bit WEP, *
			 * check if the 40-bit key matches */

			/* opt.keylen = 5; many functions use keylen. it is dangerous to do
			 * this in a multithreaded process */

			if (check_wep_key(wep.key, B, 5) == SUCCESS)
			{
				opt.keylen = 5;

				return (SUCCESS);
			}
		}

		if (B + opt.do_brute + 1 == opt.keylen && opt.do_brute)
		{
			/* as noted by Simon Marechal, it's more efficient
			 * to just bruteforce the last two keybytes. */

			/*
				Ask for removing votes here
				1. Input keybyte. Use enter when it's done => Bruteforce will
			   start
				2. Input value to remove votes from: 00 -> FF or Enter to cancel
			   remove
				3. Remove votes
				4. Redraw
				5. Go back to 1
			*/
			if (opt.visual_inspection == 1)
			{
				while (1)
				{
					// Show the current stat
					show_wep_stats(B, 1, NULL, NULL, NULL, 0);

					// Inputting user value until it hits enter or give a valid
					// value
					printf("On which keybyte do you want to remove votes (Hit "
						   "Enter when done)? ");
					memset(user_guess, 0, 4);

					charread = readLine(user_guess, 3);

					// Break if 'Enter' key was hit
					if (user_guess[0] == 0 || charread == 0) break;

					// If it's not a number, reask
					// Check if inputted value is correct (from 0 to and
					// inferior to opt.keylen)
					remove_keybyte_nr = (int) strtol(user_guess, NULL, 10);
					if (isdigit((int) user_guess[0]) == 0
						|| remove_keybyte_nr < 0
						|| remove_keybyte_nr >= opt.keylen)
						continue;

					// It's a number for sure and the number is correct
					// Now ask which value should be removed
					printf("From which keybyte value do you want to remove the "
						   "votes (Hit Enter to cancel)? ");
					memset(user_guess, 0, 4);
					charread = readLine(user_guess, 3);

					// Break if enter was hit
					if (user_guess[0] == 0 || charread == 0) continue;

					remove_keybyte_value = hexToInt(user_guess, charread);

					// Check if inputted value is correct (hexa). Value range:
					// 00 - FF
					if (remove_keybyte_value < 0 || remove_keybyte_value > 255)
						continue;

					// If correct, remove and redraw
					remove_votes(remove_keybyte_nr,
								 (unsigned char) remove_keybyte_value);
				}
			}

			if (opt.nbcpu == 1 || opt.do_mt_brute == 0)
			{
				if (opt.do_brute == 4)
				{
					for (l = 0; l < 256; l++)
					{
						wep.key[opt.brutebytes[0]] = (uint8_t) l;

						for (m = 0; m < 256; m++)
						{
							wep.key[opt.brutebytes[1]] = (uint8_t) m;

							for (i = 0; i < 256; i++)
							{
								wep.key[opt.brutebytes[2]] = (uint8_t) i;

								for (j = 0; j < 256; j++)
								{
									wep.key[opt.brutebytes[3]] = (uint8_t) j;

									if (check_wep_key(wep.key, B + 1, 0)
										== SUCCESS)
										return (SUCCESS);
								}
							}
						}
					}
				}
				else if (opt.do_brute == 3)
				{
					for (m = 0; m < 256; m++)
					{
						wep.key[opt.brutebytes[0]] = (uint8_t) m;

						for (i = 0; i < 256; i++)
						{
							wep.key[opt.brutebytes[1]] = (uint8_t) i;

							for (j = 0; j < 256; j++)
							{
								wep.key[opt.brutebytes[2]] = (uint8_t) j;

								if (check_wep_key(wep.key, B + 1, 0) == SUCCESS)
									return (SUCCESS);
							}
						}
					}
				}
				else if (opt.do_brute == 2)
				{
					for (i = 0; i < 256; i++)
					{
						wep.key[opt.brutebytes[0]] = (uint8_t) i;

						for (j = 0; j < 256; j++)
						{
							wep.key[opt.brutebytes[1]] = (uint8_t) j;

							if (check_wep_key(wep.key, B + 1, 0) == SUCCESS)
								return (SUCCESS);
						}
					}
				}
				else
				{
					for (i = 0; i < 256; i++)
					{
						wep.key[opt.brutebytes[0]] = (uint8_t) i;

						if (check_wep_key(wep.key, B + 1, 0) == SUCCESS)
							return (SUCCESS);
					}
				}
			}
			else
			{
				/* multithreaded bruteforcing of the last 2 keybytes */
				k = (k + 1) % opt.nbcpu;
				do
				{
					for (tsel = 0; tsel < opt.nbcpu && !wepkey_crack_success;
						 ++tsel)
					{
						if (bf_nkeys[(tsel + k) % opt.nbcpu] > 16)
						{
							usleep(1);
							continue;
						}
						else
						{
							/* write our current key to the pipe so it'll have
							 * its last 2 bytes bruteforced */
							bf_nkeys[(tsel + k) % opt.nbcpu]++;

							if (safe_write(bf_pipe[(tsel + k) % opt.nbcpu][1],
										   (void *) wep.key,
										   64)
								!= 64)
							{
								perror("write pmk failed");
								kill(0, SIGTERM);
								_exit(EXIT_FAILURE);
							}
							break;
						}
					}
				} while (tsel >= opt.nbcpu && !wepkey_crack_success);

				if (wepkey_crack_success)
				{
					memcpy(wep.key, bf_wepkey, (size_t) opt.keylen);
					return (SUCCESS);
				}
			}
		}
		else
		{
			switch (do_wep_crack1(B + 1))
			{
				case SUCCESS:
					return (SUCCESS);
				case RESTART:
					return (RESTART);
				default:
					break;
			}
		}
	}

	// if we are going to fail on the root byte, check again if there are still
	// threads bruting, if so wait and check again.
	if (B == 0)
	{
		for (i = 0; i < opt.nbcpu; i++)
		{
			while (bf_nkeys[i] > 0 && !wepkey_crack_success) usleep(1);
		}
		if (wepkey_crack_success)
		{
			memcpy(wep.key, bf_wepkey, (size_t) opt.keylen);
			return (SUCCESS);
		}
	}

	return (FAILURE);
}

/* experimental single bruteforce attack */

static int do_wep_crack2(int B)
{
	int i, j;

	switch (update_ivbuf())
	{
		case FAILURE:
			return (FAILURE);
		case RESTART:
			return (RESTART);
		default:
			break;
	}

	if (wep.nb_ivs_now / opt.keylen < 60000)
	{
		printf(
			"Not enough IVs available. This option is only meant to be used\n"
			"if the standard attack method fails with more than %d IVs.\n",
			opt.keylen * 60000);
		kill(0, SIGTERM);
		_exit(EXIT_FAILURE);
	}

	for (i = 0; i <= B; i++)
	{
		if (calc_poll(i) != SUCCESS) return (FAILURE);

		wep.key[i] = (uint8_t) wep.poll[i][0].idx;

		wep.fudge[i] = 1;
		wep.depth[i] = 0;

		if (!opt.is_quiet) show_wep_stats(i, 0, NULL, NULL, NULL, 0);
	}

	for (wep.fudge[B] = 1; wep.fudge[B] < 256; wep.fudge[B]++)
	{
		ALLEGE(0 <= wep.fudge[B] && wep.fudge[B] < INT_MAX); //-V560

		if ((float) wep.poll[B][wep.fudge[B]].val
			< (float) wep.poll[B][0].val / opt.ffact)
			break;
	}

	for (wep.depth[B] = 0;
		 wep.depth[B] < wep.fudge[B] && wep.fudge[B] < INT_MAX;
		 wep.depth[B]++)
	{
		switch (update_ivbuf())
		{
			case FAILURE:
				return (FAILURE);
			case RESTART:
				return (RESTART);
			default:
				break;
		}

		wep.key[B] = (uint8_t) wep.poll[B][wep.depth[B]].idx;

		if (!opt.is_quiet) show_wep_stats(B, 0, NULL, NULL, NULL, 0);

		for (i = B + 1; i < opt.keylen - 2; i++)
		{
			if (calc_poll(i) != SUCCESS) return (FAILURE);

			wep.key[i] = (uint8_t) wep.poll[i][0].idx;

			wep.fudge[i] = 1;
			wep.depth[i] = 0;

			if (!opt.is_quiet) show_wep_stats(i, 0, NULL, NULL, NULL, 0);
		}

		for (i = 0; i < 256; i++)
		{
			wep.key[opt.keylen - 2] = (uint8_t) i;

			for (j = 0; j < 256; j++)
			{
				wep.key[opt.keylen - 1] = (uint8_t) j;

				if (check_wep_key(wep.key, opt.keylen - 2, 0) == SUCCESS)
					return (SUCCESS);
			}
		}
	}

	return (FAILURE);
}

static THREAD_ENTRY(inner_bruteforcer_thread)
{
	int i, j, k, l;
	size_t nthread = (size_t) arg;
	unsigned char wepkey[64];
	void * ret = NULL;

inner_bruteforcer_thread_start:

	if (close_aircrack) return (ret);

	if (wepkey_crack_success) return ((void *) SUCCESS);

	/* we get the key for which we'll bruteforce the last 2 bytes from the pipe
	 */
	if (safe_read(bf_pipe[nthread][0], (void *) wepkey, 64) != 64)
	{
		return ((void *) FAILURE); //-V566
	}

	if (close_aircrack) return (ret);

	/* now we test the 256*256 keys... if we succeed we'll save it and exit the
	 * thread */
	if (opt.do_brute == 4)
	{
		for (l = 0; l < 256; l++)
		{
			wepkey[opt.brutebytes[0]] = (uint8_t) l;

			for (k = 0; k < 256; k++)
			{
				wepkey[opt.brutebytes[1]] = (uint8_t) k;

				for (i = 0; i < 256; i++)
				{
					wepkey[opt.brutebytes[2]] = (uint8_t) i;

					for (j = 0; j < 256; j++)
					{
						wepkey[opt.brutebytes[3]] = (uint8_t) j;

						if (check_wep_key(wepkey, opt.keylen - 2, 0) == SUCCESS)
							return ((void *) SUCCESS);
					}
				}
			}
		}
	}
	else if (opt.do_brute == 3)
	{
		for (k = 0; k < 256; k++)
		{
			wepkey[opt.brutebytes[0]] = (uint8_t) k;

			for (i = 0; i < 256; i++)
			{
				wepkey[opt.brutebytes[1]] = (uint8_t) i;

				for (j = 0; j < 256; j++)
				{
					wepkey[opt.brutebytes[2]] = (uint8_t) j;

					if (check_wep_key(wepkey, opt.keylen - 2, 0) == SUCCESS)
						return ((void *) SUCCESS);
				}
			}
		}
	}
	else if (opt.do_brute == 2)
	{
		for (i = 0; i < 256; i++)
		{
			wepkey[opt.brutebytes[0]] = (uint8_t) i;

			for (j = 0; j < 256; j++)
			{
				wepkey[opt.brutebytes[1]] = (uint8_t) j;

				if (check_wep_key(wepkey, opt.keylen - 2, 0) == SUCCESS)
					return ((void *) SUCCESS);
			}
		}
	}
	else
	{
		for (j = 0; j < 256; j++)
		{
			wepkey[opt.brutebytes[0]] = (uint8_t) j;

			if (check_wep_key(wepkey, opt.keylen - 2, 0) == SUCCESS)
				return ((void *) SUCCESS);
		}
	}

	--bf_nkeys[nthread];

	goto inner_bruteforcer_thread_start;
}

/* display the current wpa key info, matrix-like */

static void show_wpa_stats(char * key,
						   int keylen,
						   unsigned char pmk[32],
						   unsigned char ptk[64],
						   unsigned char mic[16],
						   int force)
{
	float calc;
	float ksec;
	float delta;
	int et_h;
	int et_m;
	int et_s;
	int i;
	char tmpbuf[28];
	size_t remain;
	size_t eta;
	size_t cur_nb_kprev;

	if (chrono(&t_stats, 0) < 0.15 && force == 0) return;

	if (force != 0)
		ALLEGE(pthread_mutex_lock(&mx_wpastats)
			   == 0); // if forced, wait until we can lock
	else if (pthread_mutex_trylock(&mx_wpastats)
			 != 0) // if not forced, just try
		return;

	chrono(&t_stats, 1);

	delta = chrono(&t_begin, 0);
	if (delta <= FLT_EPSILON) goto __out;

	et_s = (int) lrintf(fmodf(delta, 59.f));
	et_m = (int) lrintf(fmodf(((delta - et_s) / 60.0), 59.0f));
	if (delta >= 60.f * 60.f)
		et_h = (int) lrintf((delta - et_s - et_m) / (60.f * 60.f));
	else
		et_h = 0;

	ALLEGE(pthread_mutex_lock(&mx_nb) == 0);
	cur_nb_kprev = nb_kprev;
	ALLEGE(pthread_mutex_unlock(&mx_nb) == 0);

	ksec = (float) cur_nb_kprev / delta;
	if (ksec <= FLT_EPSILON) goto __out;

	if (_speed_test)
	{
		printf("%0.3f k/s   \r", ksec);
		fflush(stdout);

		if (_speed_test_length > 0 && delta >= (float) _speed_test_length)
		{
			printf("\n");
			exit(EXIT_SUCCESS);
		}

		goto __out;
	}

	moveto(0, 3);
	erase_display(0);

	if (opt.l33t)
	{
		textstyle(TEXT_BRIGHT);
		textcolor_fg(TEXT_YELLOW);
	}

	if (opt.stdin_dict)
	{
		moveto(20, 5);
		printf("[%02d:%02d:%02d] %zd keys tested "
			   "(%2.2f k/s) ",
			   et_h,
			   et_m,
			   et_s,
			   nb_tried,
			   ksec);
	}
	else
	{
		moveto(7, 4);
		printf("[%02d:%02d:%02d] %zd/%zd keys tested "
			   "(%2.2f k/s) ",
			   et_h,
			   et_m,
			   et_s,
			   nb_tried,
			   opt.wordcount,
			   ksec);

		moveto(7, 6);
		printf("Time left: ");

		calc = ((float) nb_tried / (float) opt.wordcount) * 100.0f;
		remain = opt.wordcount - nb_tried;

		if (remain > 0 && ksec > 0)
		{
			eta = (remain / ksec);
			calctime(eta, calc);
		}
		else
			printf("--\n");
	}

	memset(tmpbuf, ' ', sizeof(tmpbuf));
	memcpy(tmpbuf, key, (size_t) keylen > 27u ? 27u : (size_t) keylen);
	tmpbuf[27] = '\0';

	if (opt.l33t)
	{
		textstyle(TEXT_BRIGHT);
		textcolor_fg(TEXT_WHITE);
	}

	moveto(24, 8);
	printf("Current passphrase: %s\n", tmpbuf);

	if (opt.l33t)
	{
		textcolor_normal();
		textcolor_fg(TEXT_GREEN);
	}

	moveto(7, 11);
	printf("Master Key     : ");

	if (opt.l33t)
	{
		textstyle(TEXT_BRIGHT);
		textcolor_fg(TEXT_GREEN);
	}

	for (i = 0; i < 32; i++)
	{
		if (i == 16)
		{
			move(CURSOR_BACK, 32 + 16);
			move(CURSOR_DOWN, 1);
		}
		printf("%02X ", pmk[i]);
	}

	if (opt.l33t)
	{
		textcolor_normal();
		textcolor_fg(TEXT_GREEN);
	}

	moveto(7, 14);
	printf("Transient Key  : ");

	if (opt.l33t)
	{
		textstyle(TEXT_BRIGHT);
		textcolor_fg(TEXT_GREEN);
	}

	for (i = 0; i < 64; i++)
	{
		if (i > 0 && i % 16 == 0)
		{
			printf("\n");
			move(CURSOR_FORWARD, 23);
		}
		printf("%02X ", ptk[i]);
	}

	if (opt.l33t)
	{
		textcolor_normal();
		textcolor_fg(TEXT_GREEN);
	}

	moveto(7, 19);
	printf("EAPOL HMAC     : ");

	if (opt.l33t)
	{
		textstyle(TEXT_BRIGHT);
		textcolor_fg(TEXT_GREEN);
	}
	for (i = 0; i < 16; i++) printf("%02X ", mic[i]);

	printf("\n");

__out:
	ALLEGE(pthread_mutex_unlock(&mx_wpastats) == 0);
}

/**
 * Called in response to successfully cracking a WPA key.
 *
 * @param data A structure containing the WPA data.
 * @param keys An array of passphrases.
 * @param mic An array of calculated MIC codes.
 * @param nparallel The number of used slots in each array.
 * @param threadid The current thread ID number.
 * @param j The winning index, containing the successful data.
 */
static void crack_wpa_successfully_cracked(
	struct WPA_data * data,
	wpapsk_password keys[MAX_KEYS_PER_CRYPT_SUPPORTED],
	uint8_t mic[MAX_KEYS_PER_CRYPT_SUPPORTED][20],
	int nparallel,
	int threadid,
	int j)
{
	// pre-conditions
	REQUIRE(data != NULL);
	REQUIRE(keys != NULL);
	REQUIRE(mic != NULL);
	REQUIRE(nparallel > 0 && nparallel <= MAX_KEYS_PER_CRYPT_SUPPORTED);
	REQUIRE(threadid >= 0 && threadid < MAX_THREADS);
	REQUIRE(j >= 0 && j < nparallel);

	FILE * keyFile = NULL;

	// close the dictionary
	ALLEGE(pthread_mutex_lock(&mx_dic) == 0);
	if (opt.dict != NULL)
	{
		if (!opt.stdin_dict) fclose(opt.dict);
		opt.dict = NULL;
	}
	ALLEGE(pthread_mutex_unlock(&mx_dic) == 0);

	// copy working passphrase to output buffer
	memset(data->key, 0, sizeof(data->key));
	memcpy(data->key, keys[j].v, sizeof(keys[0].v));

	// Write the key to a file
	if (opt.logKeyToFile != NULL)
	{
		keyFile = fopen(opt.logKeyToFile, "w");
		if (keyFile != NULL)
		{
			fprintf(keyFile, "%s", keys[j].v);
			ALLEGE(fclose(keyFile) != -1);
		}
	}

	wpa_cracked = 1; // Inform producer we're done.

	if (opt.is_quiet)
	{
		return;
	}

	increment_passphrase_counts(keys, nparallel);

	show_wpa_stats((char *) keys[j].v,
				   keys[j].length,
				   dso_ac_crypto_engine_get_pmk(&engine, threadid, j),
				   dso_ac_crypto_engine_get_ptk(&engine, threadid, j),
				   mic[j],
				   1);

	if (opt.l33t)
	{
		textstyle(TEXT_BRIGHT);
		textcolor_fg(TEXT_RED);
	}

	moveto((80 - 15 - (int) keys[j].length) / 2, 8);
	erase_line(2);
	printf("KEY FOUND! [ %s ]\n", keys[j].v);
	move(CURSOR_DOWN, 11);

	if (opt.l33t)
	{
		textcolor_normal();
		textcolor_fg(TEXT_GREEN);
	}
}

// Given a tainted passphrase, this calculate the
// number of leading, validate bytes for \a key.
static inline int calculate_passphrase_length(uint8_t * key)
{
	REQUIRE(key != NULL);

	int i = (int) strnlen((const char *) key, MAX_PASSPHRASE_LENGTH + 3);

	// ensure NULL termination, after strnlen.
	key[i] = '\0';

	// trim newlines
	while (i > 0 && (key[i - 1] == '\r' || key[i - 1] == '\n')) i--;

	// truncate long passphrases
	if (i > MAX_PASSPHRASE_LENGTH + 1) i = 64;

	// ensure NULL termination, after above checks
	key[i] = '\0';

	// ensure only valid characters in byte sequence.
	for (int j = 0; j < i; j++)
		if (!isascii(key[j]) || key[j] < 32) i = 0;

	// returns the length of the valid passphrase sequence
	return (i);
}

static THREAD_ENTRY(crack_wpa_thread)
{
	REQUIRE(arg != NULL);

	uint8_t mic[MAX_KEYS_PER_CRYPT_SUPPORTED][20] __attribute__((aligned(32)));
	wpapsk_password keys[MAX_KEYS_PER_CRYPT_SUPPORTED]
		__attribute__((aligned(64)));
	char essid[128] __attribute__((aligned(16)));

	struct WPA_data * data;
	struct AP_info * ap;
	int threadid = 0;
	void * ret = NULL;
	int i;
	int j;

	int nparallel = dso_ac_crypto_engine_simd_width();

	data = (struct WPA_data *) arg;
	ap = data->ap;
	threadid = data->threadid;
	memcpy(essid, ap->essid, ESSID_LENGTH + 1);

	// The attack below requires a full handshake.
	ALLEGE(ap->wpa.state == 7);

	dso_ac_crypto_engine_thread_init(&engine, threadid);

#ifdef XDEBUG
	if (nparallel > 1)
		fprintf(stderr,
				"The Crypto Engine will crack %d in parallel.\n",
				nparallel);
	else
		fprintf(stderr,
				"WARNING: The Crypto Engine is unable to crack in parallel.\n");
#endif

	dso_ac_crypto_engine_calc_pke(&engine,
								  ap->bssid,
								  ap->wpa.stmac,
								  ap->wpa.anonce,
								  ap->wpa.snonce,
								  threadid);

#ifdef XDEBUG
	printf("Thread # %d starting...\n", threadid);
#endif

	bool done = false;
	while (!done) // Continue until HAZARD value seen.
	{
		memset(keys, 0, sizeof(keys));

		for (j = 0; !done && j < nparallel; ++j)
		{
			uint8_t * our_key = keys[j].v;
			i = 0;

			do
			{
				wpa_receive_passphrase((char *) our_key, data);

				// Do we see our HAZARD value?
				if (our_key[0] == 0xff && our_key[1] == 0xff
					&& our_key[2] == 0xff
					&& our_key[3] == 0xff)
				{
					done = true; // Yes!
					break; // Exit for loop; process remaining.
				}

				i = calculate_passphrase_length(keys[j].v);
			} while ((size_t) i < MIN_WPA_PASSPHRASE_LEN);

			keys[j].length = (uint32_t) i;
#ifdef XDEBUG
			printf("%lu: GOT %p: %s\n", pthread_self(), our_key, our_key);
#endif
		}

		if (unlikely((j = dso_ac_crypto_engine_wpa_crack(&engine,
														 keys,
														 ap->wpa.eapol,
														 ap->wpa.eapol_size,
														 mic,
														 ap->wpa.keyver,
														 ap->wpa.keymic,
														 nparallel,
														 threadid))
					 >= 0))
		{
#ifdef XDEBUG
			printf("%d - %lu FOUND IT AT %d %p !\n",
				   threadid,
				   pthread_self(),
				   j,
				   keys[j].v);
#endif
			crack_wpa_successfully_cracked(
				data, keys, mic, nparallel, threadid, j);
		}

		increment_passphrase_counts(keys, nparallel);

		if (threadid == first_wpa_threadid && !opt.is_quiet)
		{
			show_wpa_stats((char *) keys[0].v,
						   keys[0].length,
						   dso_ac_crypto_engine_get_pmk(&engine, threadid, 0),
						   dso_ac_crypto_engine_get_ptk(&engine, threadid, 0),
						   mic[0],
						   0);
		}
	}

	ALLEGE(pthread_mutex_lock(&(data->mutex)) == 0);
	data->active = 0; // We are no longer an active consumer.
	ALLEGE(pthread_mutex_unlock(&(data->mutex)) == 0);

	dso_ac_crypto_engine_thread_destroy(&engine, threadid);

	return (ret);
}

static THREAD_ENTRY(crack_wpa_pmkid_thread)
{
	REQUIRE(arg != NULL);

	uint8_t mic[MAX_KEYS_PER_CRYPT_SUPPORTED][20] __attribute__((aligned(32)));
	wpapsk_password keys[MAX_KEYS_PER_CRYPT_SUPPORTED]
		__attribute__((aligned(64)));
	char essid[128] __attribute__((aligned(16)));

	struct WPA_data * data;
	struct AP_info * ap;
	int threadid = 0;
	void * ret = NULL;
	int i;
	int j;
	int nparallel = dso_ac_crypto_engine_simd_width();

	data = (struct WPA_data *) arg;
	ap = data->ap;
	threadid = data->threadid;
	memcpy(essid, ap->essid, ESSID_LENGTH + 1);

	// Check some pre-conditions.
	ALLEGE(ap->wpa.state > 0 && ap->wpa.state < 7);
	ALLEGE(ap->wpa.pmkid[0] != 0x00);

	dso_ac_crypto_engine_thread_init(&engine, threadid);

	dso_ac_crypto_engine_set_pmkid_salt(
		&engine, ap->bssid, ap->wpa.stmac, threadid);

#ifdef XDEBUG
	printf("Thread # %d starting...\n", threadid);
#endif

	bool done = false;
	while (!done) // Loop until our HAZARD value is seen.
	{
		memset(keys, 0, sizeof(keys));

		for (j = 0; !done && j < nparallel; ++j)
		{
			uint8_t * our_key = keys[j].v;
			i = 0;

			do
			{
				wpa_receive_passphrase((char *) our_key, data);

				// Do we see our HAZARD value?
				if (our_key[0] == 0xff && our_key[1] == 0xff
					&& our_key[2] == 0xff
					&& our_key[3] == 0xff)
				{
					done = true; // Yes!
					break; // Exit for loop; process remaining.
				}

				i = calculate_passphrase_length(keys[j].v);
			} while ((size_t) i < MIN_WPA_PASSPHRASE_LEN);

			keys[j].length = (uint32_t) i;
#ifdef XDEBUG
			printf("%lu: GOT %p: %s\n", pthread_self(), our_key, our_key);
#endif
		}

		if (unlikely((j = dso_ac_crypto_engine_wpa_pmkid_crack(
						  &engine, keys, ap->wpa.pmkid, nparallel, threadid))
					 >= 0))
		{
#ifdef XDEBUG
			printf("%d - %lu FOUND IT AT %d %p !\n",
				   threadid,
				   pthread_self(),
				   j,
				   keys[j].v);
#endif
			crack_wpa_successfully_cracked(
				data, keys, mic, nparallel, threadid, j);
		}

		increment_passphrase_counts(keys, nparallel);

		if (first_wpa_threadid == threadid && !opt.is_quiet)
		{
			show_wpa_stats((char *) keys[0].v,
						   keys[0].length,
						   dso_ac_crypto_engine_get_pmk(&engine, threadid, 0),
						   dso_ac_crypto_engine_get_ptk(&engine, threadid, 0),
						   mic[0],
						   0);
		}
	}

	ALLEGE(pthread_mutex_lock(&(data->mutex)) == 0);
	data->active = 0; // We are no longer an ACTIVE consumer.
	ALLEGE(pthread_mutex_unlock(&(data->mutex)) == 0);

	dso_ac_crypto_engine_thread_destroy(&engine, threadid);

	return (ret);
}

/**
 * Open a specific dictionary
 * nb: index of the dictionary
 * return 0 on success and FAILURE if it failed
 */
static __attribute__((noinline)) int next_dict(int nb)
{
	size_t tmpword = 0;

	ALLEGE(nb >= 0);

	ALLEGE(pthread_mutex_lock(&mx_dic) == 0);
	if (opt.dict != NULL)
	{
		if (!opt.stdin_dict) fclose(opt.dict);
		opt.dict = NULL;
	}
	opt.nbdict = nb;

	while (opt.nbdict < MAX_DICTS && opt.dicts[opt.nbdict] != NULL)
	{
		if (strcmp(opt.dicts[opt.nbdict], "-") == 0)
		{
			opt.stdin_dict = 1;
			opt.dictfinish = 1; // no ETA stats on stdin

			if ((opt.dict = fdopen(fileno(stdin), "r")) == NULL)
			{
				perror("fdopen(stdin) failed");
				opt.nbdict++;
				continue;
			}

			opt.no_stdin = 1;
		}
		else
		{
			opt.stdin_dict = 0;
			if ((opt.dict = fopen(opt.dicts[opt.nbdict], "r")) == NULL)
			{
				printf("ERROR: Opening dictionary %s failed (%s)\n",
					   opt.dicts[opt.nbdict],
					   strerror(errno));
				opt.nbdict++;
				continue;
			}

			ALLEGE(fseeko(opt.dict, 0L, SEEK_END) != -1);

			if (ftello(opt.dict) <= 0L)
			{
				printf("ERROR: Processing dictionary file %s (%s)\n",
					   opt.dicts[opt.nbdict],
					   strerror(errno));
				fclose(opt.dict);
				opt.dict = NULL;
				opt.nbdict++;
				continue;
			}

			if (!opt.dictfinish)
			{
				chrono(&t_dictup, 1);
				opt.dictidx[opt.nbdict].dictsize = ftello(opt.dict);

				if (!opt.dictidx[opt.nbdict].dictpos
					|| (opt.dictidx[opt.nbdict].dictpos
						> opt.dictidx[opt.nbdict].dictsize))
				{
					tmpword = linecount(opt.dicts[opt.nbdict],
										(opt.dictidx[opt.nbdict].dictpos
											 ? opt.dictidx[opt.nbdict].dictpos
											 : 0),
										READBUF_MAX_BLOCKS);

					opt.dictidx[opt.nbdict].wordcount += tmpword;
					opt.wordcount += tmpword;
					opt.dictidx[opt.nbdict].dictpos
						= (READBUF_BLKSIZE * READBUF_MAX_BLOCKS);
				}
			}

			rewind(opt.dict);
		}
		break;
	}

	ALLEGE(pthread_mutex_unlock(&mx_dic) == 0);

	if (opt.nbdict >= MAX_DICTS || opt.dicts[opt.nbdict] == NULL)
		return (FAILURE);

	// Update wordlist ID and position in session
	if (cracking_session)
	{
		ALLEGE(pthread_mutex_lock(&(cracking_session->mutex)) == 0);

		cracking_session->pos = 0;
		cracking_session->wordlist_id = (uint8_t) opt.nbdict;

		ALLEGE(pthread_mutex_unlock(&(cracking_session->mutex)) == 0);
	}

	return (SUCCESS);
}

#ifdef HAVE_SQLITE
static int
sql_wpacallback(void * arg, int ccount, char ** values, char ** columnnames)
{
	UNUSED_PARAM(ccount);
	UNUSED_PARAM(values);
	UNUSED_PARAM(columnnames);
	REQUIRE(arg != NULL);

	struct AP_info * ap = (struct AP_info *) arg;

	unsigned char ptk[80];
	unsigned char mic[20];
	FILE * keyFile;

	calc_mic(ap, (unsigned char *) values[0], ptk, mic);

	if (memcmp(mic, ap->wpa.keymic, 16) == 0)
	{
		// Write the key to a file
		if (opt.logKeyToFile != NULL)
		{
			keyFile = fopen(opt.logKeyToFile, "w");
			if (keyFile != NULL)
			{
				fprintf(keyFile, "%s", values[1]);
				ALLEGE(fclose(keyFile) != -1);
			}
		}

		if (opt.is_quiet)
		{
			printf("KEY FOUND! [ %s ]\n", values[1]);
			return (FAILURE);
		}

		show_wpa_stats(values[1],
					   (int) strlen(values[1]),
					   (unsigned char *) (values[0]),
					   ptk,
					   mic,
					   1);

		if (opt.l33t)
		{
			textstyle(TEXT_BRIGHT);
			textcolor_fg(TEXT_RED);
		}

		moveto((80 - 15 - (int) strlen(values[1])) / 2, 8);
		erase_line(2);
		printf("KEY FOUND! [ %s ]\n", values[1]);
		move(CURSOR_DOWN, 11);

		if (opt.l33t)
		{
			textcolor_normal();
			textcolor_fg(TEXT_GREEN);
		}

		// abort the query
		return (FAILURE);
	}

	ALLEGE(pthread_mutex_lock(&mx_nb) == 0);
	nb_tried++;
	nb_kprev++;
	ALLEGE(pthread_mutex_unlock(&mx_nb) == 0);

	if (!opt.is_quiet)
		show_wpa_stats(values[1],
					   (int) strlen(values[1]),
					   (unsigned char *) (values[0]),
					   ptk,
					   mic,
					   0);

	return (SUCCESS);
}
#endif

static int __attribute__((noinline))
display_wpa_hash_information(struct AP_info * ap_cur)
{
	unsigned i = 0;

	if (ap_cur == NULL)
	{
		printf("No valid WPA handshakes found.\n");
		return (FAILURE);
	}

	if (memcmp(ap_cur->essid, ZERO, ESSID_LENGTH) == 0 && !opt.essid_set)
	{
		printf("An ESSID is required. Try option -e.\n");
		return (FAILURE);
	}

	if (opt.essid_set && ap_cur->essid[0] == '\0')
	{
		memcpy(ap_cur->essid, opt.essid, sizeof(ap_cur->essid));
	}

	printf("[*] ESSID (length: %d): %s\n",
		   (int) ustrlen(ap_cur->essid),
		   ap_cur->essid);

	printf("[*] Key version: %d\n", ap_cur->wpa.keyver);

	printf("[*] BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
		   ap_cur->bssid[0],
		   ap_cur->bssid[1],
		   ap_cur->bssid[2],
		   ap_cur->bssid[3],
		   ap_cur->bssid[4],
		   ap_cur->bssid[5]);
	printf("[*] STA: %02X:%02X:%02X:%02X:%02X:%02X",
		   ap_cur->wpa.stmac[0],
		   ap_cur->wpa.stmac[1],
		   ap_cur->wpa.stmac[2],
		   ap_cur->wpa.stmac[3],
		   ap_cur->wpa.stmac[4],
		   ap_cur->wpa.stmac[5]);

	printf("\n[*] anonce:");
	for (i = 0; i < sizeof(ap_cur->wpa.anonce); i++)
	{
		if (i % 16 == 0) printf("\n    ");
		printf("%02X ", ap_cur->wpa.anonce[i]);
	}

	printf("\n[*] snonce:");
	for (i = 0; i < sizeof(ap_cur->wpa.snonce); i++)
	{
		if (i % 16 == 0) printf("\n    ");
		printf("%02X ", ap_cur->wpa.snonce[i]);
	}

	printf("\n[*] Key MIC:\n   ");
	for (i = 0; i < sizeof(ap_cur->wpa.keymic); i++)
	{
		printf(" %02X", ap_cur->wpa.keymic[i]);
	}

	printf("\n[*] eapol:");
	for (i = 0; i < ap_cur->wpa.eapol_size; i++)
	{
		if (i % 16 == 0) printf("\n    ");
		printf("%02X ", ap_cur->wpa.eapol[i]);
	}

	return (SUCCESS);
}

static int do_make_wkp(struct AP_info * ap_cur)
{
	REQUIRE(ap_cur != NULL);

	size_t elt_written;

	printf("\n\nBuilding WKP file...\n\n");
	if (display_wpa_hash_information(ap_cur) != 0)
	{
		return (FAILURE);
	}
	printf("\n");

	// write file
	FILE * fp_wkp;
	char frametmp[WKP_FRAME_LENGTH];
	char * ptmp;

	memcpy(frametmp, wkp_frame, WKP_FRAME_LENGTH * sizeof(char));

	// Make sure the filename contains the extension
	if (!(string_has_suffix(opt.wkp, ".wkp")
		  || string_has_suffix(opt.wkp, ".WKP")))
	{
		strcat(opt.wkp, ".wkp");
	}

	fp_wkp = fopen(opt.wkp, "w");
	if (fp_wkp == NULL)
	{
		printf("\nFailed to create EWSA project file\n");
		return (FAILURE);
	}

	// ESSID
	memcpy(&frametmp[0x4c0], ap_cur->essid, sizeof(ap_cur->essid));

	// BSSID
	ptmp = (char *) ap_cur->bssid;
	memcpy(&frametmp[0x514], ptmp, ETHER_ADDR_LEN);

	// Station Mac
	ptmp = (char *) ap_cur->wpa.stmac;
	memcpy(&frametmp[0x51a], ptmp, ETHER_ADDR_LEN);

	// ESSID
	memcpy(&frametmp[0x520], ap_cur->essid, sizeof(ap_cur->essid));

	// ESSID length
	frametmp[0x540] = (uint8_t) ustrlen(ap_cur->essid);

	// WPA Key version
	frametmp[0x544] = ap_cur->wpa.keyver;

	// Size of EAPOL
	frametmp[0x548] = (uint8_t) ap_cur->wpa.eapol_size;

	// anonce
	ptmp = (char *) ap_cur->wpa.anonce;
	memcpy(&frametmp[0x54c], ptmp, sizeof(ap_cur->wpa.anonce));

	// snonce
	ptmp = (char *) ap_cur->wpa.snonce;
	memcpy(&frametmp[0x56c], ptmp, sizeof(ap_cur->wpa.snonce));

	// EAPOL
	ptmp = (char *) ap_cur->wpa.eapol;
	memcpy(&frametmp[0x58c], ptmp, ap_cur->wpa.eapol_size);

	// Key MIC
	ptmp = (char *) ap_cur->wpa.keymic;
	memcpy(&frametmp[0x68c], ptmp, 16);

	elt_written = fwrite(frametmp, 1, WKP_FRAME_LENGTH, fp_wkp);
	ALLEGE(fclose(fp_wkp) != -1);

	if ((int) elt_written == WKP_FRAME_LENGTH)
	{
		printf("\nSuccessfully written to %s\n", opt.wkp);
		return (SUCCESS);
	}
	else
	{
		printf("\nFailed to write to %s\n !", opt.wkp);
		return (FAILURE);
	}
}

// return by value because it is the simplest interface and we call this
// infrequently
static hccap_t ap_to_hccap(struct AP_info * ap)
{
	REQUIRE(ap != NULL);

	hccap_t hccap;

	memset(&hccap, 0, sizeof(hccap));
	ap->wpa.state = 7;
	ap->crypt = 3;

	memcpy(&hccap.essid, &ap->essid, sizeof(ap->essid));
	memcpy(&hccap.mac1, &ap->bssid, sizeof(ap->bssid));
	memcpy(&hccap.mac2, &ap->wpa.stmac, sizeof(ap->wpa.stmac));
	memcpy(&hccap.nonce1, &ap->wpa.snonce, sizeof(ap->wpa.snonce));
	memcpy(&hccap.nonce2, &ap->wpa.anonce, sizeof(ap->wpa.anonce));
	memcpy(&hccap.eapol, &ap->wpa.eapol, sizeof(ap->wpa.eapol));
	memcpy(&hccap.eapol_size, &ap->wpa.eapol_size, sizeof(ap->wpa.eapol_size));
	memcpy(&hccap.keyver, &ap->wpa.keyver, sizeof(ap->wpa.keyver));
	memcpy(&hccap.keymic, &ap->wpa.keymic, sizeof(ap->wpa.keymic));

	return (hccap);
}

#if 0
// Caller must free
__attribute__((unused)) static struct AP_info * hccap_to_ap(hccap_t * hccap)
{
	REQUIRE(hccap != NULL);

	struct AP_info * ap = malloc(sizeof(struct AP_info));
	ALLEGE(ap != NULL);
	memset(&ap, 0, sizeof(ap));

	memcpy(&ap->essid, &hccap->essid, sizeof(ap->essid)); //-V512
	memcpy(&ap->bssid, &hccap->mac1, sizeof(ap->bssid));
	memcpy(&ap->wpa.stmac, &hccap->mac2, sizeof(hccap->mac2));
	memcpy(&ap->wpa.snonce, &hccap->nonce1, sizeof(hccap->nonce1));
	memcpy(&ap->wpa.anonce, &hccap->nonce2, sizeof(hccap->nonce2));
	memcpy(&ap->wpa.eapol, &hccap->eapol, sizeof(hccap->eapol));
	memcpy(&ap->wpa.eapol_size, &hccap->eapol_size, sizeof(hccap->eapol_size));
	memcpy(&ap->wpa.keyver, &hccap->keyver, sizeof(ap->wpa.keyver));
	memcpy(&ap->wpa.keymic, &hccap->keymic, sizeof(hccap->keymic));

	return (ap);
}
#endif

static int do_make_hccap(struct AP_info * ap_cur)
{
	REQUIRE(ap_cur != NULL);

	size_t elt_written;

	printf("\n\nBuilding Hashcat file...\n\n");
	if (display_wpa_hash_information(ap_cur) != 0)
	{
		return (FAILURE);
	}
	printf("\n");

	// write file
	FILE * fp_hccap;

	strcat(opt.hccap, ".hccap");

	fp_hccap = fopen(opt.hccap, "wb");
	if (fp_hccap == NULL)
	{
		printf("\nFailed to create Hashcat capture file\n");
		return (FAILURE);
	}

	hccap_t hccap = ap_to_hccap(ap_cur);

	elt_written = fwrite(&hccap, sizeof(hccap_t), 1, fp_hccap);
	ALLEGE(fclose(fp_hccap) != -1);

	if (elt_written == 1u)
	{
		printf("\nSuccessfully written to %s\n", opt.hccap);
		return (SUCCESS);
	}
	else
	{
		printf("\nFailed to write to %s\n !", opt.hccap);
		return (FAILURE);
	}
}

// Caller must free
struct AP_info * hccapx_to_ap(struct hccapx * hx)
{
	REQUIRE(hx != NULL);

	struct AP_info * ap = malloc(sizeof(struct AP_info));
	ALLEGE(ap != NULL);
	memset(ap, 0, sizeof(struct AP_info));
	ap->wpa.state = 7;
	ap->crypt = 3;

	ALLEGE((MIN(sizeof(hx->essid), sizeof(ap->essid))) <= 32); //-V547
	memcpy(&ap->essid, //-V512
		   &hx->essid,
		   MIN(sizeof(hx->essid), sizeof(ap->essid)));
	memcpy(&ap->bssid, &hx->mac_ap, sizeof(hx->mac_ap));
	memcpy(&ap->wpa.stmac, &hx->mac_sta, sizeof(hx->mac_sta));
	memcpy(&ap->wpa.snonce, &hx->nonce_sta, sizeof(hx->nonce_sta));
	memcpy(&ap->wpa.anonce, &hx->nonce_ap, sizeof(hx->nonce_ap));
	memcpy(&ap->wpa.eapol, &hx->eapol, sizeof(hx->eapol));
	memcpy(&ap->wpa.keyver, &hx->keyver, sizeof(hx->keyver));
	memcpy(&ap->wpa.keymic, &hx->keymic, sizeof(hx->keymic));

	assert(sizeof(hx->eapol_len) == 2);
	ap->wpa.eapol_size = le16_to_cpu(hx->eapol_len);

	return (ap);
}

// See: https://hashcat.net/wiki/doku.php?id=hccapx
static struct MessagePairLUT
{
	uint8_t found_mask;
	uint8_t eapol_mask;
	uint8_t message_pair;
} message_pair_lookup_table[] = {
	{(1 << 1) + (1 << 2), (1 << 2), 128},
	{(1 << 1) + (1 << 4), (1 << 4), 129},
	{(1 << 2) + (1 << 3), (1 << 2), 130},
	{(1 << 2) + (1 << 3), (1 << 3), 131},
	{(1 << 3) + (1 << 4), (1 << 3), 132},
	{(1 << 3) + (1 << 4), (1 << 4), 133},
};

static hccapx_t ap_to_hccapx(struct AP_info * ap)
{
	REQUIRE(ap != NULL);

	struct hccapx hx;
	uint32_t temp;
	uint8_t ssid_len;

	memset(&hx, 0, sizeof(hx));

	temp = cpu_to_le32(HCCAPX_SIGNATURE);
	memcpy(&hx.signature, &temp, sizeof(temp));
	temp = cpu_to_le32(HCCAPX_CURRENT_VERSION);
	memcpy(&hx.version, &temp, sizeof(temp));

	hx.message_pair = 0;
	for (size_t i = 0; i < ArrayCount(message_pair_lookup_table); ++i)
	{
		const struct MessagePairLUT * item = &message_pair_lookup_table[i];
		if ((ap->wpa.found & item->found_mask) == item->found_mask
			&& (ap->wpa.eapol_source & item->eapol_mask) != 0)
		{
			hx.message_pair = item->message_pair;
		}
	}
	ALLEGE(hx.message_pair > 0);

	if ((ap->wpa.eapol_source & (1 << 3)) != 0)
	{
		fprintf(stderr,
				"WARNING: The created HCCAPX file will not be able to "
				"properly convert back to PCAP format.\n");

		if (ap->wpa.eapol_size >= sizeof(hx.eapol))
		{
			fprintf(stderr,
					"FATAL: EAPOL data from M3 exceeds maximum size of "
					"255 bytes.\n");
		}
	}

	ssid_len = (uint8_t) ustrlen(ap->essid);
	memcpy(&hx.essid_len, &ssid_len, sizeof(ssid_len));

	memcpy(&hx.essid, &ap->essid, sizeof(hx.essid)); //-V512
	memcpy(&hx.mac_ap, &ap->bssid, sizeof(ap->bssid));
	memcpy(&hx.mac_sta, &ap->wpa.stmac, sizeof(ap->wpa.stmac));
	memcpy(&hx.keyver, &ap->wpa.keyver, sizeof(ap->wpa.keyver));
	memcpy(&hx.keymic, &ap->wpa.keymic, sizeof(ap->wpa.keymic));
	memcpy(&hx.nonce_sta, &ap->wpa.snonce, sizeof(ap->wpa.snonce));
	memcpy(&hx.nonce_ap, &ap->wpa.anonce, sizeof(ap->wpa.anonce));
	hx.eapol_len = cpu_to_le16((uint16_t) ap->wpa.eapol_size);
	memcpy(&hx.eapol, &ap->wpa.eapol, sizeof(ap->wpa.eapol));

	return (hx);
}

static int do_make_hccapx(struct AP_info * ap_cur)
{
	REQUIRE(ap_cur != NULL);

	size_t elt_written;

	printf("\n\nBuilding Hashcat (3.60+) file...\n\n");
	if (display_wpa_hash_information(ap_cur) != 0)
	{
		return (FAILURE);
	}
	printf("\n");

	// write file
	FILE * fp_hccapx;

	strcat(opt.hccapx, ".hccapx");

	fp_hccapx = fopen(opt.hccapx, "wb");
	if (fp_hccapx == NULL)
	{
		printf("\nFailed to create Hashcat X capture file\n");
		return (FAILURE);
	}

	struct hccapx hx = ap_to_hccapx(ap_cur);

	elt_written = fwrite(&hx, sizeof(struct hccapx), 1, fp_hccapx);
	ALLEGE(fclose(fp_hccapx) != -1);

	if ((int) elt_written == 1)
	{
		printf("\nSuccessfully written to %s\n", opt.hccapx);
		return (SUCCESS);
	}
	else
	{
		printf("\nFailed to write to %s\n !", opt.hccapx);
		return (FAILURE);
	}
}

static int do_wpa_crack(void)
{
	int cid;
	char key1[128];

	// display program banner
	if (!opt.is_quiet && !_speed_test)
	{
		if (opt.l33t) textcolor(TEXT_RESET, TEXT_WHITE, TEXT_BLACK);

		erase_display(2);

		if (opt.l33t)
		{
			textstyle(TEXT_BRIGHT);
			textcolor_fg(TEXT_BLUE);
		}

		moveto((80 - (int) strlen(progname)) / 2, 2);
		printf("%s", progname);
	}

	// Initial thread to communicate with.
	cid = 0;

	// Loop until no passphrases or one is found.
	while (!wpa_cracked && !close_aircrack)
	{
		// clear passphrase buffer.
		memset(key1, 0, sizeof(key1));
		if (_speed_test)
			strcpy(key1, "sorbosorbo");
		else
		{
			ALLEGE(pthread_mutex_lock(&mx_dic) == 0);
			if (opt.dict == NULL
				|| fgets(key1, sizeof(key1) - 1, opt.dict) == NULL)
			{
				ALLEGE(pthread_mutex_unlock(&mx_dic) == 0);

				if (opt.l33t)
				{
					textcolor_normal();
					textcolor_fg(TEXT_GREEN);
				}
				if (next_dict(opt.nbdict + 1) != 0)
				{
					return (FAILURE);
				}
				else
					continue;
			}
			else
				ALLEGE(pthread_mutex_unlock(&mx_dic) == 0);

			// Validate incoming passphrase meets the following criteria:
			// a. is not the pipeline shutdown sentinel.
			// b. is at least 8 bytes and roughly UTF-8 compatible.
			if (((uint8_t) key1[0] == 0xff && (uint8_t) key1[1] == 0xff)
				|| (size_t) calculate_passphrase_length((uint8_t *) key1)
					   < MIN_WPA_PASSPHRASE_LEN)
			{
				ALLEGE(pthread_mutex_lock(&mx_nb) == 0);
				++nb_tried;
				ALLEGE(pthread_mutex_unlock(&mx_nb) == 0);

				continue;
			}
		}

		/* count number of lines in next wordlist chunk */
		wl_count_next_block(&(wpa_data[cid]));

		/* send the passphrase */
		cid = (cid + 1) % opt.nbcpu;

		(void) wpa_send_passphrase(key1, &(wpa_data[cid]), 1);
	}

	return (FAILURE);
}

static int next_key(char ** key, int keysize)
{
	REQUIRE(key != NULL);
	REQUIRE(keysize > 0);

	char *tmp, *tmpref;
	int i, rtn;
	unsigned int dec;
	char * hex;

	tmpref = tmp = (char *) malloc(1024);
	ALLEGE(tmpref != NULL);
	ALLEGE(tmp != NULL);

	while (1)
	{
		rtn = 0;
		ALLEGE(pthread_mutex_lock(&mx_dic) == 0);
		if (opt.dict == NULL)
		{
			ALLEGE(pthread_mutex_unlock(&mx_dic) == 0);
			free(tmpref);
			tmp = NULL;
			return (FAILURE);
		}
		else
			ALLEGE(pthread_mutex_unlock(&mx_dic) == 0);

		if (opt.hexdict[opt.nbdict])
		{
			ALLEGE(pthread_mutex_lock(&mx_dic) == 0);
			if (fgets(tmp, ((keysize * 2) + (keysize - 1)), opt.dict) == NULL)
			{
				ALLEGE(pthread_mutex_unlock(&mx_dic) == 0);
				if (opt.l33t)
				{
					textcolor_normal();
					textcolor_fg(TEXT_GREEN);
				}

				if (next_dict(opt.nbdict + 1) != 0)
				{
					free(tmpref);
					tmp = NULL;
					return (FAILURE);
				}
				else
					continue;
			}
			else
				ALLEGE(pthread_mutex_unlock(&mx_dic) == 0);

			i = (int) strlen(tmp);

			if (i <= 2) continue;

			if (tmp[i - 1] == '\n') tmp[--i] = '\0';
			if (tmp[i - 1] == '\r') tmp[--i] = '\0';

			i = 0;

			hex = strsep(&tmp, ":");

			while (i < keysize && hex != NULL)
			{
				const size_t hex_len = strlen(hex);
				if (hex_len == 0 || hex_len > 2)
				{
					rtn = 1;
					break;
				}
				if (sscanf(hex, "%x", &dec) == 0)
				{
					rtn = 1;
					break;
				}

				(*key)[i] = (uint8_t) dec;
				hex = strsep(&tmp, ":");
				i++;
			}
			if (rtn)
			{
				continue;
			}
		}
		else
		{
			ALLEGE(pthread_mutex_lock(&mx_dic) == 0);
			if (fgets(*key, keysize, opt.dict) == NULL)
			{
				ALLEGE(pthread_mutex_unlock(&mx_dic) == 0);
				if (opt.l33t)
				{
					textcolor_normal();
					textcolor_fg(TEXT_GREEN);
				}

				if (next_dict(opt.nbdict + 1) != 0)
				{
					free(tmpref);
					tmp = NULL;
					return (FAILURE);
				}
				else
					continue;
			}
			else
				ALLEGE(pthread_mutex_unlock(&mx_dic) == 0);

			i = (int) strlen(*key);

			if (i <= 2) continue;
			if (i >= 64) continue;

			if ((*key)[i - 1] == '\n') (*key)[--i] = '\0';
			if ((*key)[i - 1] == '\r') (*key)[--i] = '\0';
		}

		break;
	}

	free(tmpref);
	return (SUCCESS);
}

static int set_dicts(const char * args)
{
	REQUIRE(args != NULL);

	int len;
	char * optargs = strdup(args);
	char * poptargs = optargs;
	char * optarg;

	if (optargs == NULL)
	{
		perror("Failed to allocate memory for arguments");
		return (FAILURE);
	}

	ALLEGE(pthread_mutex_lock(&mx_dic) == 0);
	opt.dictfinish = opt.totaldicts = opt.nbdict = 0;
	ALLEGE(pthread_mutex_unlock(&mx_dic) == 0);

	// Use a temporary poptargs var because \a strsep trashes the value.
	while ((opt.nbdict < MAX_DICTS)
		   && (optarg = strsep(&poptargs, ",")) != NULL)
	{
		if (!strncasecmp(optarg, "h:", 2))
		{
			optarg += 2;
			opt.hexdict[opt.nbdict] = 1;
		}
		else
		{
			opt.hexdict[opt.nbdict] = 0;
		}

		if (!(opt.dicts[opt.nbdict] = strdup(optarg)))
		{
			free(optargs);
			perror("Failed to allocate memory for dictionary");
			return (FAILURE);
		}

		ALLEGE(pthread_mutex_lock(&mx_dic) == 0);
		opt.nbdict++;
		opt.totaldicts++;
		ALLEGE(pthread_mutex_unlock(&mx_dic) == 0);
	}
	free(optargs);

	for (len = opt.nbdict; len < MAX_DICTS; len++) opt.dicts[len] = NULL;

	next_dict(0);

	while (next_dict(opt.nbdict + 1) == 0)
	{
	}

	next_dict(0);

	return (0);
}

/*
Uses the specified dictionary to crack the WEP key.

Return: SUCCESS if it cracked the key,
		FAILURE if it could not.
*/
static int crack_wep_dict(void)
{
	struct timeval t_last;
	struct timeval t_now;
	int i, origlen, keysize;
	char * key;

	keysize = opt.keylen + 1;

	update_ivbuf();

	if (wep.nb_ivs < TEST_MIN_IVS)
	{
		printf("\n%ld IVs is below the minimum required for a dictionary "
			   "attack (%d IVs min.)!\n",
			   wep.nb_ivs,
			   TEST_MIN_IVS);
		return (FAILURE);
	}

	key = (char *) malloc(sizeof(char) * (opt.keylen + 1));
	if (key == NULL) return (FAILURE);

	gettimeofday(&t_last, NULL);
	t_last.tv_sec--;

	while (1)
	{
		if (next_key(&key, keysize) != SUCCESS)
		{
			free(key);
			return (FAILURE);
		}

		i = (int) strlen(key);

		origlen = i;

		while (i < opt.keylen)
		{
			key[i] = key[i - origlen];
			i++;
		}

		key[i] = '\0';

		if (!opt.is_quiet)
		{
			gettimeofday(&t_now, NULL);
			if ((t_now.tv_sec - t_last.tv_sec) > 0)
			{
				show_wep_stats(opt.keylen - 1, 1, NULL, NULL, NULL, 0);
				gettimeofday(&t_last, NULL);
			}
		}

		for (i = 0; i <= opt.keylen; i++)
		{
			wep.key[i] = (unsigned char) key[i];
		}

		if (check_wep_key(wep.key, opt.keylen, 0) == SUCCESS)
		{
			free(key);
			wepkey_crack_success = 1;
			return (SUCCESS);
		}
	}
}

/*
Uses the PTW attack to crack the WEP key.

Return: SUCCESS if it cracked the key,
		FAILURE if it could not.
*/
static int crack_wep_ptw(struct AP_info * ap_cur)
{
	REQUIRE(ap_cur != NULL);

	int(*all)[256];
	int i, j, len = 0;

	opt.ap = ap_cur;

	all = malloc(32 * sizeof(int[256]));
	ALLEGE(all != NULL);

	// initial setup (complete keyspace)
	memset(all, 1, 32 * sizeof(int[256]));

	// setting restricted keyspace
	for (i = 0; i < 32; i++)
	{
		for (j = 0; j < 256; j++)
		{
			if ((opt.is_alnum && (j < 32 || j >= 128))
				|| (opt.is_fritz && (j < 48 || j >= 58))
				|| (opt.is_bcdonly && (j > 0x99 || (j & 0x0F) > 0x09)))
				all[i][j] = 0;
		}
	}

	// if debug is specified, force a specific value.
	for (i = 0; i < 32; i++)
	{
		for (j = 0; j < 256; j++)
		{
			if (opt.debug_row[i] == 1 && opt.debug[i] != j)
				all[i][j] = 0;
			else if (opt.debug_row[i] == 1 && opt.debug[i] == j)
				all[i][j] = 1;
		}
	}

	if (ap_cur->nb_ivs_clean > 99)
	{
		ap_cur->nb_ivs = ap_cur->nb_ivs_clean;
		// first try without bruteforcing, using only "clean" keystreams
		if (opt.keylen != 13)
		{
			if (PTW_computeKey(ap_cur->ptw_clean,
							   wep.key,
							   opt.keylen,
							   (int) (KEYLIMIT * opt.ffact),
							   PTW_DEFAULTBF,
							   all,
							   opt.ptw_attack)
				== 1)
				len = opt.keylen;
		}
		else
		{
			/* try 1000 40bit keys first, to find the key "instantly" and you
			 * don't need to wait for 104bit to fail */
			if (PTW_computeKey(ap_cur->ptw_clean,
							   wep.key,
							   5,
							   1000,
							   PTW_DEFAULTBF,
							   all,
							   opt.ptw_attack)
				== 1)
				len = 5;
			else if (PTW_computeKey(ap_cur->ptw_clean,
									wep.key,
									13,
									(int) (KEYLIMIT * opt.ffact),
									PTW_DEFAULTBF,
									all,
									opt.ptw_attack)
					 == 1)
				len = 13;
			else if (PTW_computeKey(ap_cur->ptw_clean,
									wep.key,
									5,
									(int) (KEYLIMIT * opt.ffact) / 3,
									PTW_DEFAULTBF,
									all,
									opt.ptw_attack)
					 == 1)
				len = 5;
		}
	}
	if (!len)
	{
		ap_cur->nb_ivs = ap_cur->nb_ivs_vague;
		// in case it's not found, try bruteforcing the id field and include
		// "vague" keystreams
		PTW_DEFAULTBF[10] = 1;
		PTW_DEFAULTBF[11] = 1;

		if (opt.keylen != 13)
		{
			if (PTW_computeKey(ap_cur->ptw_vague,
							   wep.key,
							   opt.keylen,
							   (int) (KEYLIMIT * opt.ffact),
							   PTW_DEFAULTBF,
							   all,
							   opt.ptw_attack)
				== 1)
				len = opt.keylen;
		}
		else
		{
			/* try 1000 40bit keys first, to find the key "instantly" and you
			 * don't need to wait for 104bit to fail */
			if (PTW_computeKey(ap_cur->ptw_vague,
							   wep.key,
							   5,
							   1000,
							   PTW_DEFAULTBF,
							   all,
							   opt.ptw_attack)
				== 1)
				len = 5;
			else if (PTW_computeKey(ap_cur->ptw_vague,
									wep.key,
									13,
									(int) (KEYLIMIT * opt.ffact),
									PTW_DEFAULTBF,
									all,
									opt.ptw_attack)
					 == 1)
				len = 13;
			else if (PTW_computeKey(ap_cur->ptw_vague,
									wep.key,
									5,
									(int) (KEYLIMIT * opt.ffact) / 10,
									PTW_DEFAULTBF,
									all,
									opt.ptw_attack)
					 == 1)
				len = 5;
		}
	}

	free(all);

	if (!len) return (FAILURE);

	opt.probability = 100;
	key_found(wep.key, len, -1);

	return (SUCCESS);
}

static int missing_wordlist_dictionary(struct AP_info * ap_cur)
{
	REQUIRE(ap_cur != NULL);

	if (opt.wkp == NULL && opt.hccap == NULL && opt.hccapx == NULL)
	{
		printf("Please specify a dictionary (option -w).\n");
	}
	else
	{
		if (opt.wkp)
		{
			return (do_make_wkp(ap_cur));
		}
		if (opt.hccap)
		{
			return (do_make_hccap(ap_cur));
		}
		if (opt.hccapx)
		{
			return (do_make_hccapx(ap_cur));
		}
	}

	return (SUCCESS);
}

static int perform_wep_crack(struct AP_info * ap_cur)
{
	REQUIRE(ap_cur != NULL);

	int ret = FAILURE;
	int j = 0;
	struct winsize ws;

	if (ioctl(0, TIOCGWINSZ, &ws) < 0)
	{
		ws.ws_row = 25;
		ws.ws_col = 80;
	}

	/* Default key length: 128 bits */
	if (opt.keylen == 0) opt.keylen = 13;

	if (j + opt.do_brute > 4)
	{
		printf("Bruteforcing more than 4 bytes will take too long, aborting!");
		return (FAILURE);
	}

	for (int i = 0; i < opt.do_brute; i++)
	{
		opt.brutebytes[j + i] = opt.keylen - 1 - i;
	}

	opt.do_brute += j;

	if (opt.ffact <= FLT_EPSILON)
	{
		if (opt.do_ptw)
			opt.ffact = 2;
		else
		{
			if (!opt.do_testy)
			{
				if (opt.keylen == 5)
					opt.ffact = 5;
				else
					opt.ffact = 2;
			}
			else
				opt.ffact = 30;
		}
	}

	memset(&wep, 0, sizeof(wep));

	if (opt.do_ptw)
	{
		if (!opt.is_quiet)
			printf("Attack will be restarted every %d captured ivs.\n",
				   PTW_TRY_STEP);
		opt.next_ptw_try = (int) (ap_cur->nb_ivs_vague
								  - (ap_cur->nb_ivs_vague % PTW_TRY_STEP));
		do
		{
			if (!opt.is_quiet)
			{
				char buf[1024];
				snprintf(buf,
						 sizeof(buf),
						 "Got %ld out of %d IVs",
						 ap_cur->nb_ivs_vague,
						 opt.next_ptw_try);
				moveto((ws.ws_col - (int) strlen(buf)) / 2, 6);
				fputs(buf, stdout);
				erase_line(0);
			}

			if (ap_cur->nb_ivs_vague >= opt.next_ptw_try)
			{
				if (!opt.is_quiet)
					printf("Starting PTW attack with %ld ivs.\n",
						   ap_cur->nb_ivs_vague);
				ret = crack_wep_ptw(ap_cur);
				ALLEGE(ret >= 0 && ret <= RESTART); //-V560

				if (opt.oneshot == 1 && ret == FAILURE)
				{
					printf("   Attack failed. Possible reasons:\n\n"
						   "     * Out of luck: you must capture more IVs. "
						   "Usually, 104-bit WEP\n"
						   "       can be cracked with about 80 000 IVs, "
						   "sometimes more.\n\n"
						   "     * Try to raise the fudge factor (-f).\n");
					ret = 0;
				}

				if (ret)
				{
					opt.next_ptw_try += PTW_TRY_STEP;
					printf("Failed. Next try with %d IVs.\n", opt.next_ptw_try);
				}
			}
			if (ret) usleep(8000);
		} while (!close_aircrack && ret != 0);
	}

	if (close_aircrack)
		return (FAILURE);

	else if (opt.dict != NULL)
	{
		ret = crack_wep_dict();
		ALLEGE(ret >= 0 && ret <= RESTART); //-V560
	}
	else
	{
		for (int i = 0; i < opt.nbcpu; i++)
		{
			/* start one thread per cpu */

			if (opt.amode <= 1 && opt.nbcpu > 1 && opt.do_brute
				&& opt.do_mt_brute)
			{
				if (pthread_create(&(tid[id]),
								   NULL,
								   &inner_bruteforcer_thread,
								   (void *) (long) i)
					!= 0)
				{
					perror("pthread_create failed");
					return (FAILURE);
				}
				id++;
			}

			if (pthread_create(
					&(tid[id]), NULL, &crack_wep_thread, (void *) (long) i)
				!= 0)
			{
				perror("pthread_create failed");
				return (FAILURE);
			}
			id++;
		}

		if (!opt.do_testy)
		{
			do
			{
				ret = do_wep_crack1(0);
				ALLEGE(ret >= 0 && ret <= RESTART); //-V560
			} while (ret == RESTART);

			if (ret == FAILURE)
			{
				printf("   Attack failed. Possible reasons:\n\n"
					   "     * Out of luck: you must capture more IVs. "
					   "Usually, 104-bit WEP\n"
					   "       can be cracked with about one million IVs, "
					   "sometimes more.\n\n"
					   "     * If all votes seem equal, or if there are "
					   "many negative votes,\n"
					   "       then the capture file is corrupted, or the "
					   "key is not static.\n\n"
					   "     * A false positive prevented the key from "
					   "being found.  Try to\n"
					   "       disable each korek attack (-k 1 .. 17), "
					   "raise the fudge factor\n"
					   "       (-f)");
				if (opt.do_testy)
					printf("and try the experimental bruteforce attacks "
						   "(-y).");
				printf("\n");
			}
		}
		else
		{
			for (int i = opt.keylen - 3; i < opt.keylen - 2; i++)
			{
				do
				{
					ret = do_wep_crack2(i);
					ALLEGE(ret >= 0 && ret <= RESTART); //-V560
				} while (ret == RESTART);

				if (ret == SUCCESS) break;
			}

			if (ret == FAILURE)
			{
				printf("   Attack failed. Possible reasons:\n\n"
					   "     * Out of luck: you must capture more IVs. "
					   "Usually, 104-bit WEP\n"
					   "       can be cracked with about one million IVs, "
					   "sometimes more.\n\n"
					   "     * If all votes seem equal, or if there are "
					   "many negative votes,\n"
					   "       then the capture file is corrupted, or the "
					   "key is not static.\n\n"
					   "     * A false positive prevented the key from "
					   "being found.  Try to\n"
					   "       disable each korek attack (-k 1 .. 17), "
					   "raise the fudge factor\n"
					   "       (-f)");
				if (opt.do_testy)
					printf("or try the standard attack mode instead (no -y "
						   "option).");
				printf("\n");
			}
		}
	}

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-overflow"
#endif
	ALLEGE(ret >= 0 && ret <= RESTART);
	if (opt.is_quiet != 1 && ret == FAILURE)
	{
		struct winsize ws;

		if (ioctl(0, TIOCGWINSZ, &ws) < 0)
		{
			ws.ws_row = 25;
			ws.ws_col = 80;
		}

		moveto((ws.ws_col - 13) / 2, 5);
		erase_line(2);
		printf("KEY NOT FOUND\n");
		moveto(0, 24);
	}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

	return (ret);
}

static int perform_wpa_crack(struct AP_info * ap_cur)
{
	REQUIRE(ap_cur != NULL);

#ifdef HAVE_SQLITE
	int rc;
	char * zErrMsg = 0;
	const char looper[4] = {'|', '/', '-', '\\'};
	int looperc = 0;
	int waited = 0;
	const char * sqlformat
		= "SELECT pmk.PMK, passwd.passwd FROM pmk INNER JOIN "
		  "passwd ON passwd.passwd_id = pmk.passwd_id INNER JOIN "
		  "essid ON essid.essid_id = pmk.essid_id WHERE "
		  "essid.essid = '%q'";
	char * sql;
#endif

	dso_ac_crypto_engine_init(&engine);

	if (opt.dict == NULL && db == NULL)
	{
		return (missing_wordlist_dictionary(ap_cur));
	}

	cpuset = ac_cpuset_new();
	ALLEGE(cpuset);
	ac_cpuset_init(cpuset);
	ac_cpuset_distribute(cpuset, (size_t) opt.nbcpu);

	ap_cur = get_first_target();

	if (ap_cur == NULL)
	{
		printf("No valid WPA handshakes found.\n");
		return (FAILURE);
	}

	if (memcmp(ap_cur->essid, ZERO, ESSID_LENGTH) == 0 && !opt.essid_set)
	{
		printf("An ESSID is required. Try option -e.\n");
		return (FAILURE);
	}

	if (opt.essid_set && ap_cur->essid[0] == '\0')
	{
		memcpy(ap_cur->essid, opt.essid, sizeof(ap_cur->essid));
	}

	dso_ac_crypto_engine_set_essid(&engine, ap_cur->essid);

	if (db == NULL)
	{
		int starting_thread_id = id;
		first_wpa_threadid = id;

		ALLEGE(opt.nbcpu >= 1);

		for (int i = 0; i < opt.nbcpu; i++)
		{
			if (ap_cur->ivbuf_size)
			{
				free(ap_cur->ivbuf);
				ap_cur->ivbuf = NULL;
				ap_cur->ivbuf_size = 0;
			}

			uniqueiv_wipe(ap_cur->uiv_root);
			ap_cur->uiv_root = NULL;
			ap_cur->nb_ivs = 0;

			// assumption: an eapol exists.
			if (ap_cur->wpa.state <= 0)
			{
				fprintf(stderr,
						"Packets contained no EAPOL data; unable "
						"to process this AP.\n");
				return (FAILURE);
			}

			const size_t key_size = MAX_PASSPHRASE_LENGTH + 1;
			const size_t kb_size = WL_CIRCULAR_QUEUE_SIZE * key_size;

			/* start one thread per cpu */
			wpa_data[i].active = 1;
			wpa_data[i].ap = ap_cur;
			wpa_data[i].thread = i;
			wpa_data[i].threadid = id;
#if HAVE_POSIX_MEMALIGN
			if (posix_memalign((void **) &(wpa_data[i].key_buffer),
							   CACHELINE_SIZE,
							   kb_size))
				perror("posix_memalign");
#else
			wpa_data[i].key_buffer = calloc(1, kb_size);
#endif
			ALLEGE(wpa_data[i].key_buffer);
			wpa_data[i].cqueue = circular_queue_init(
				wpa_data[i].key_buffer, kb_size, key_size);
			ALLEGE(wpa_data[i].cqueue);
			memset(wpa_data[i].key, 0, sizeof(wpa_data[i].key));
			ALLEGE(pthread_mutex_init(&wpa_data[i].mutex, NULL) == 0);

			if (pthread_create(&(tid[id]),
							   NULL,
							   (ap_cur->wpa.state == 7
									? &crack_wpa_thread
									: &crack_wpa_pmkid_thread),
							   (void *) &(wpa_data[i]))
				!= 0)
			{
				perror("pthread_create failed");
				return (FAILURE);
			}

			ac_cpuset_bind_thread_at(cpuset, tid[id], (size_t) i);

			id++;
		}

		int ret = do_wpa_crack(); // we feed keys to the cracking threads

		// Shutdown the circular queue.
		bool shutdown;
		do
		{
			shutdown = true;

			for (int i = 0; i < opt.nbcpu; ++i)
			{
				int active;

				if (close_aircrack_fast || wpa_cracked)
				{
					circular_queue_reset(wpa_data[i].cqueue);
				}

				ALLEGE(pthread_mutex_lock(&(wpa_data[i].mutex)) == 0);
				active = wpa_data[i].active;
				ALLEGE(pthread_mutex_unlock(&(wpa_data[i].mutex)) == 0);

				if (active)
				{
					bool result = circular_queue_try_push(
									  wpa_data[i].cqueue, "\xff\xff\xff\xff", 4)
								  == 0;
					if (!result) shutdown = false;
				}
			}
		} while (!shutdown);

		// we wait for the cracking threads to end
		for (int i = starting_thread_id; i < opt.nbcpu + starting_thread_id;
			 i++)
			if (tid[i] != 0)
			{
				ALLEGE(pthread_join(tid[i], NULL) == 0);
				tid[i] = 0;
			}

		// find the matching passphrase
		int i;
		for (i = 0; i < opt.nbcpu; i++)
		{
			if (wpa_data[i].key[0] != 0)
			{
				ret = SUCCESS;
				break;
			}
		}

		if (ret == SUCCESS)
		{
			if (opt.is_quiet)
			{
				printf("KEY FOUND! [ %s ]\n", wpa_data[i].key);
				clean_exit(EXIT_SUCCESS);
				return (SUCCESS);
			}

			if (opt.l33t)
			{
				textstyle(TEXT_BRIGHT);
				textcolor_fg(TEXT_RED);
			}

			moveto((80 - 15 - (int) strlen(wpa_data[i].key)) / 2, 8);
			erase_line(2);
			printf("KEY FOUND! [ %s ]\n", wpa_data[i].key);
			move(CURSOR_DOWN, 11);

			if (opt.l33t)
			{
				textcolor_normal();
				textcolor_fg(TEXT_GREEN);
			}

			moveto(0, 22);

			clean_exit(EXIT_SUCCESS);
		}
		else if (!close_aircrack)
		{
			if (opt.is_quiet)
			{
				printf("\nKEY NOT FOUND\n");
				clean_exit(EXIT_FAILURE);
				return (FAILURE);
			}

			if (opt.stdin_dict)
			{
				moveto(30, 5);
				printf(" %zd\n", nb_tried);
			}
			else
			{
				uint8_t ptk[64] = {0};
				uint8_t mic[32] = {0};

				show_wpa_stats(wpa_data[i].key,
							   (int) strlen(wpa_data[i].key),
							   (unsigned char *) (wpa_data[i].key),
							   ptk,
							   mic,
							   1);

				moveto((80 - 13) / 2, 8);
				erase_line(2);
				printf("KEY NOT FOUND\n");

				moveto(0, 22);
			}
		}
	}
#ifdef HAVE_SQLITE
	else
	{
		if (!opt.is_quiet && !_speed_test)
		{
			if (opt.l33t) textcolor(TEXT_RESET, TEXT_WHITE, TEXT_BLACK);
			erase_line(2);
			if (opt.l33t) textcolor(TEXT_BRIGHT, TEXT_BLUE, TEXT_BLACK);
			moveto((80 - (int) strlen(progname)) / 2, 2);
			printf("%s", progname);
		}
		sql = sqlite3_mprintf(sqlformat, ap_cur->essid);
		while (1)
		{
			rc = sqlite3_exec(db, sql, sql_wpacallback, ap_cur, &zErrMsg);
			if (rc == SQLITE_LOCKED || rc == SQLITE_BUSY)
			{
				fprintf(stdout,
						"Database is locked or busy. Waiting %is ... %1c    \r",
						++waited,
						looper[looperc]);
				fflush(stdout);
				looperc = (looperc + 1) % sizeof(looper);
				sleep(1);
				if (zErrMsg)
				{
					sqlite3_free(zErrMsg);
					zErrMsg = NULL;
				}
			}
			else
			{
				if (rc != SQLITE_OK && rc != SQLITE_ABORT)
				{
					fprintf(stderr, "SQL error: %s\n", zErrMsg);
				}
				if (waited != 0) printf("\n\n");
				wpa_wordlists_done = 1;
				if (zErrMsg)
				{
					sqlite3_free(zErrMsg);
					zErrMsg = NULL;
				}
				break;
			}
		}
		sqlite3_free(sql);
	}
#endif

	return (SUCCESS);
}

#if DYNAMIC
static void load_aircrack_crypto_dso(int simd_features)
{
	simd_init();

	if (simd_features == -1)
	{
		simd_features = simd_get_supported_features();
		simd_features &= ac_crypto_engine_loader_get_available();
	}

	if (ac_crypto_engine_loader_load(simd_features) != 0) exit(EXIT_FAILURE);

	simd_destroy();
}
#endif

int main(int argc, char * argv[])
{
	int i, n, ret, option, j, ret1, nbMergeBSSID;
	int cpu_count, showhelp, z, zz, forceptw;
	char *s, buf[128];
	struct AP_info * ap_cur = NULL;
	int old = 0;
	char essid[ESSID_LENGTH + 1];
	int restore_session = 0;
#if defined(__i386__) || defined(__x86_64__) || defined(__arm__)               \
	|| defined(__aarch64__)
	int in_use_simdsize = 0;
#endif
	int nbarg = argc;
	access_points = c_avl_create(station_compare);
	targets = c_avl_create(station_compare);

	ac_crypto_init();

	ret = FAILURE;
	showhelp = 0;

	// Start a new process group, we are perhaps going to call kill(0, ...)
	// later
	setsid();

	memset(&opt, 0, sizeof(opt));

	rand_init();

	memset(mc_pipe, -1, sizeof(mc_pipe));
	memset(cm_pipe, -1, sizeof(cm_pipe));
	memset(bf_pipe, -1, sizeof(bf_pipe));

#if DYNAMIC
	// Load the best available shared library, or the user specified one.
	int simd_features = -1;
	if (argc >= 2 && strncmp(argv[1], "--simd=", 7) == 0)
	{
		const char * simd = &argv[1][7];

		simd_features = ac_crypto_engine_loader_string_to_flag(simd);

		if (simd_features < SIMD_SUPPORTS_NONE)
		{
			fprintf(stderr, "Unknown SIMD architecture.\n");
			exit(EXIT_FAILURE);
		}
	}

	load_aircrack_crypto_dso(simd_features);
#endif

	// Get number of CPU (return -1 if failed).
	cpu_count = get_nb_cpus();
	opt.nbcpu = 1;
	if (cpu_count > 1)
	{
		opt.nbcpu = cpu_count;
	}

	db = NULL;
	/* check the arguments */

	opt.nbdict = 0;
	opt.amode = 0;
	opt.do_brute = 1;
	opt.do_mt_brute = 1;
	opt.showASCII = 0;
	opt.probability = 51;
	opt.next_ptw_try = 0;
	opt.do_ptw = 1;
	opt.max_ivs = INT_MAX;
	opt.visual_inspection = 0;
	opt.firstbssid = NULL;
	opt.bssid_list_1st = NULL;
	opt.bssidmerge = NULL;
	opt.oneshot = 0;
	opt.logKeyToFile = NULL;
	opt.wkp = NULL;
	opt.hccap = NULL;
	opt.forced_amode = 0;
	opt.hccapx = NULL;

	forceptw = 0;

	ALLEGE(signal(SIGINT, sighandler) != SIG_ERR);
	ALLEGE(signal(SIGQUIT, sighandler) != SIG_ERR);
	ALLEGE(signal(SIGTERM, sighandler) != SIG_ERR);
	ALLEGE(signal(SIGALRM, SIG_IGN) != SIG_ERR);

	ALLEGE(pthread_mutex_init(&mx_apl, NULL) == 0);
	ALLEGE(pthread_mutex_init(&mx_ivb, NULL) == 0);
	ALLEGE(pthread_mutex_init(&mx_eof, NULL) == 0);
	ALLEGE(pthread_mutex_init(&mx_dic, NULL) == 0);
	ALLEGE(pthread_cond_init(&cv_eof, NULL) == 0);

	// When no params, no point checking/parsing arguments
	if (nbarg == 1)
	{
		showhelp = 1;
		goto usage;
	}

	// Check if we are restoring from a session
	if (nbarg == 3 && (strcmp(argv[1], "--restore-session") == 0
					   || strcmp(argv[1], "-R") == 0))
	{
		cracking_session = ac_session_load(argv[2]);
		if (cracking_session == NULL)
		{
			fprintf(stderr, "Failed loading session file: %s\n", argv[2]);
			return (EXIT_FAILURE);
		}
		nbarg = cracking_session->argc;
		printf("Restoring session\n");
		restore_session = 1;
	}

	while (1)
	{

		int option_index = 0;

		static const struct option long_options[]
			= {{"bssid", 1, 0, 'b'},
			   {"debug", 1, 0, 'd'},
			   {"combine", 0, 0, 'C'},
			   {"help", 0, 0, 'H'},
			   {"wep-decloak", 0, 0, 'D'},
			   {"ptw-debug", 1, 0, 'P'},
			   {"visual-inspection", 0, 0, 'V'},
			   {"oneshot", 0, 0, '1'},
			   {"cpu-detect", 0, 0, 'u'},
			   {"new-session", 1, 0, 'N'},
			   // Even though it's taken care of above, we need to
			   // handle the case where it's used along with other
			   // parameters.
			   {"restore-session", 1, 0, 'R'},
			   {"simd", 1, 0, 'W'},
			   {"simd-list", 0, 0, 0},
			   {0, 0, 0, 0}};

		// Load argc/argv either from the cracking session or from arguments
		option = getopt_long(
			nbarg,
			((restore_session && cracking_session) ? cracking_session->argv
												   : argv),
			"r:a:e:b:p:qcthd:l:E:J:m:n:i:f:k:x::XysZ:w:0HKC:M:DP:zV1Suj:N:R:I:",
			long_options,
			&option_index);

		if (option < 0) break;

		if (option_index >= 0)
		{
			if (strncmp(long_options[option_index].name, "simd-list", 9) == 0)
			{
				int simd_found = ac_crypto_engine_loader_get_available();
				char * simd_list
					= ac_crypto_engine_loader_flags_to_string(simd_found);

				printf("%s\n", simd_list);

				free(simd_list);

				exit(EXIT_SUCCESS);
			}
		}

		switch (option)
		{
			case 'N':
				// New session
				if (cracking_session == NULL)
				{
					// Ignore if there is a cracking session (which means it was
					// loaded from it)
					cracking_session
						= ac_session_from_argv(nbarg, argv, optarg);
					if (cracking_session == NULL)
					{
						return (EXIT_FAILURE);
					}
				}
				break;
			case 'R':
				// Restore and continue session
				fprintf(stderr, "This option must be used alone!\n");
				return (EXIT_FAILURE);

			case 'W':
				break;

			case 'S':
				_speed_test = 1;
				break;

			case 'I':
				_pmkid_16800 = 1;
				memset((char *) _pmkid_16800_str, 0, sizeof(_pmkid_16800_str));
				strlcpy((char *) _pmkid_16800_str,
						optarg,
						sizeof(_pmkid_16800_str));
				break;

			case 'Z':
				_speed_test_length = strtol(optarg, NULL, 10);
				if (errno == ERANGE)
				{
					fprintf(stderr, "Invalid speed test length given.\n");
					return (EXIT_FAILURE);
				}
				break;

			case ':':
			case '?':

				printf("\"%s --help\" for help.\n", argv[0]);
				return (EXIT_FAILURE);

			case 'u':
#if defined(__i386__) || defined(__x86_64__) || defined(__arm__)               \
	|| defined(__aarch64__)
				cpuid_getinfo();
				in_use_simdsize = dso_ac_crypto_engine_simd_width();
				printf("SIMD size in use= %d ", in_use_simdsize);

				if (in_use_simdsize == 1)
					printf("(64 bit)\n");
				else if (in_use_simdsize == 4)
					printf("(128 bit)\n");
				else if (in_use_simdsize == 8)
					printf("(256 bit)\n");
				else if (in_use_simdsize == 16)
					printf("(512 bit)\n");
				else
					printf("(unknown)\n");
#else
				printf("Nb CPU detected: %d\n", cpu_count);
#endif
				return (EXIT_SUCCESS);

			case 'V':
				if (forceptw)
				{
					printf("Visual inspection can only be used with KoreK\n");
					printf("Use \"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				opt.visual_inspection = 1;
				opt.do_ptw = 0;
				break;

			case 'a':

				opt.amode = (int) strtol(optarg, NULL, 10);

				if (strcasecmp(optarg, "wep") == 0)
					opt.amode = 1;

				else if (strcasecmp(optarg, "wpa") == 0)
					opt.amode = 2;

				else if (strcasecmp(optarg, "80211w") == 0)
					opt.amode = 3;

				if (opt.amode != 1 && opt.amode != 2 && opt.amode != 3)
				{
					printf(
						"Invalid attack mode. [1,2,3] or [wep,wpa,80211w]\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

#if !defined(HAVE_OPENSSL_CMAC_H) && !defined(GCRYPT_WITH_CMAC_AES)
				if (opt.amode == 3)
				{
					fprintf(stderr,
							"Key version 3 is only supported when OpenSSL (or "
							"similar) supports CMAC.\n");

					return (EXIT_FAILURE);
				}
#endif /* !HAVE_OPENSSL_CMAC_H && !GCRYPT_WITH_CMAC_AES */

				opt.forced_amode = 1;

				break;

			case 'e':

				memset(opt.essid, 0, sizeof(opt.essid));
				memcpy(
					opt.essid, optarg, MIN(strlen(optarg), sizeof(opt.essid)));
				opt.essid_set = 1;
				break;

			case 'b':

				if (getmac(optarg, 1, opt.bssid) != 0)
				{
					printf("Invalid BSSID (not a MAC).\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				opt.bssid_set = 1;
				break;

			case 'p':
			{
				int const nbcpu = (int) strtol(optarg, NULL, 10);
				if (nbcpu < 1 || nbcpu > MAX_THREADS)
				{
					printf("Invalid number of processes (recommended: %d)\n",
						   cpu_count);
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}
				if (nbcpu > cpu_count)
				{
					fprintf(stderr,
							"Specifying more processes (%d) than available "
							"CPUs (%d) would cause performance degradation.\n",
							nbcpu,
							cpu_count);
					opt.nbcpu = cpu_count;
				}
				else
					opt.nbcpu = nbcpu;

				break;
			}

			case 'q':

				opt.is_quiet = 1;

				break;

			case 'c':

				opt.is_alnum = 1;
				break;

			case 'D':

				opt.wep_decloak = 1;
				break;

			case 'h':

				opt.is_fritz = 1;
				break;

			case 't':

				opt.is_bcdonly = 1;
				break;

			case '1':

				opt.oneshot = 1;
				break;

			case 'd':

				i = 0;
				n = 0;
				s = optarg;
				while (s[i] != '\0')
				{
					if (s[i] == 'x') s[i] = 'X';
					if (s[i] == 'y') s[i] = 'Y';
					if (s[i] == '-' || s[i] == ':' || s[i] == ' ')
						i++;
					else
						s[n++] = s[i++];
				}
				s[n] = '\0';
				buf[0] = s[0];
				buf[1] = s[1];
				buf[2] = '\0';
				i = 0;
				j = 0;
				while ((sscanf(buf, "%d", &n) == 1)
					   || (buf[0] == 'X' && buf[1] == 'X')
					   || (buf[0] == 'Y' && buf[1] == 'Y'))
				{
					if (buf[0] == 'X' && buf[1] == 'X')
					{
						opt.debug_row[i++] = 0;
					}
					else if (buf[0] == 'Y' && buf[1] == 'Y')
					{
						opt.brutebytes[j++] = i++;
					}
					else
					{
						if (n < 0 || n > 255)
						{
							printf("Invalid debug key.\n");
							printf("\"%s --help\" for help.\n", argv[0]);
							return (EXIT_FAILURE);
						}
						opt.debug[i] = (uint8_t) n;
						opt.debug_row[i++] = 1;
					}
					if (i >= 64) break;
					s += 2;
					buf[0] = s[0];
					buf[1] = s[1];
				}

				opt.do_ptw = 0;
				break;

			case 'm':

				if (getmac(optarg, 1, opt.maddr) != 0)
				{
					printf("Invalid MAC address filter.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				break;

			case 'n':

				opt.keylen = (int) strtol(optarg, NULL, 10);
				if (opt.keylen != 64 && opt.keylen != 128 && opt.keylen != 152
					&& opt.keylen != 256
					&& opt.keylen != 512)
				{
					printf("Invalid WEP key length. [64,128,152,256,512]\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				opt.keylen = (opt.keylen / 8) - 3;

				break;

			case 'i':

				opt.index = (int) strtol(optarg, NULL, 10);
				if (opt.index < 1 || opt.index > 4)
				{
					printf("Invalid WEP key index. [1-4]\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				break;

			case 'f':

				opt.ffact = (int) strtol(optarg, NULL, 10);
				if (opt.ffact < 1)
				{
					printf("Invalid fudge factor. [>=1]\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				break;

			case 'k':

				opt.korek = (int) strtol(optarg, NULL, 10);
				if (opt.korek < 1 || opt.korek > N_ATTACKS)
				{
					printf("Invalid KoreK attack strategy. [1-%d]\n",
						   N_ATTACKS);
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				K_COEFF[(opt.korek) - 1] = 0;

				break;

			case 'l':
			{
				const size_t optarg_len = strlen(optarg) + 1;
				opt.logKeyToFile = (char *) calloc(1, optarg_len);
				if (opt.logKeyToFile == NULL)
				{
					printf("Error allocating memory\n");
					return (EXIT_FAILURE);
				}

				strlcpy(opt.logKeyToFile, optarg, optarg_len);
			}
			break;

			case 'E':
			{
				// Make sure there's enough space for file
				// extension just in case it was forgotten
				const size_t wkp_len = strlen(optarg) + 6;
				opt.wkp = (char *) calloc(1, wkp_len);
				if (opt.wkp == NULL)
				{
					printf("Error allocating memory\n");
					return (EXIT_FAILURE);
				}

				strlcpy(opt.wkp, optarg, wkp_len);
			}
			break;

			case 'J':
			{
				// Make sure there's enough space for file
				// extension just in case it was forgotten
				const size_t hccap_len = strlen(optarg) + 8;
				opt.hccap = (char *) calloc(1, hccap_len);
				if (opt.hccap == NULL)
				{
					printf("Error allocating memory\n");
					return (EXIT_FAILURE);
				}

				strlcpy(opt.hccap, optarg, hccap_len);
			}
			break;

			case 'j':
			{
				// Make sure there's enough space for file
				// extension just in case it was forgotten
				const size_t hccapx_len = strlen(optarg) + 8;
				opt.hccapx = (char *) calloc(1, hccapx_len);
				if (opt.hccapx == NULL)
				{
					printf("Error allocating memory\n");
					return (EXIT_FAILURE);
				}

				strlcpy(opt.hccapx, optarg, hccapx_len);
			}
			break;

			case 'M':

				opt.max_ivs = (int) strtol(optarg, NULL, 10);
				if (opt.max_ivs < 1)
				{
					printf("Invalid number of max. ivs [>=1]\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				K_COEFF[(opt.korek) - 1] = 0;

				break;

			case 'P':

				opt.ptw_attack = (int) strtol(optarg, NULL, 10);
				if (errno == EINVAL || opt.ptw_attack < 0 || opt.ptw_attack > 2)
				{
					printf("Invalid number for ptw debug [0-2]\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				break;

			case 'x':

				opt.do_brute = 0;

				if (optarg)
				{
					opt.do_brute = (int) strtol(optarg, NULL, 10);
					if (errno == EINVAL || opt.do_brute < 0 || opt.do_brute > 4)
					{
						printf("Invalid option -x%s. [0-4]\n", optarg);
						printf("\"%s --help\" for help.\n", argv[0]);
						return (EXIT_FAILURE);
					}
				}

				break;

			case 'X':

				opt.do_mt_brute = 0;
				break;

			case 'y':

				opt.do_testy = 1;
				break;

			case 'K':

				opt.do_ptw = 0;
				break;

			case 's':

				opt.showASCII = 1;
				break;

			case 'w':

				if (set_dicts(optarg) != 0)
				{
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				opt.do_ptw = 0;
				break;

			case 'r':

#ifdef HAVE_SQLITE
				if (sqlite3_open(optarg, &db))
				{
					fprintf(stderr, "Database error: %s\n", sqlite3_errmsg(db));
					sqlite3_close(db);
					return (EXIT_FAILURE);
				}
#else
				fprintf(
					stderr,
					"Error: Aircrack-ng wasn't compiled with sqlite support\n");
				return (EXIT_FAILURE);
#endif
				break;

			case '0':

				opt.l33t = 1;
				break;

			case 'H':

				showhelp = 1;
				goto usage;
				break;

			case 'C':

				nbMergeBSSID = checkbssids(optarg);

				if (nbMergeBSSID < 1 || nbMergeBSSID >= INT_MAX)
				{
					printf("Invalid bssids (-C).\n\"%s --help\" for help.\n",
						   argv[0]);
					return (EXIT_FAILURE);
				}

				// Useless to merge BSSID if only one element
				if (nbMergeBSSID == 1)
					printf(
						"Merging BSSID disabled, only one BSSID specified\n");
				else
					opt.bssidmerge = optarg;

				break;

			case 'z':

				/* only for backwards compatibility - PTW used by default */
				if (opt.visual_inspection)
				{
					printf("Visual inspection can only be used with KoreK\n");
					printf("Use \"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}

				forceptw = 1;

				break;

			default:
				goto usage;
		}
	}

	if (_speed_test)
	{
		if (opt.forced_amode != 1)
		{
			// default to WPA-PSK (2)
			opt.amode = 2;
		}
		opt.dict = stdin;
		opt.bssid_set = 1;

		ap_cur = malloc(sizeof(*ap_cur));
		if (!ap_cur) err(1, "malloc()");

		memset(ap_cur, 0, sizeof(*ap_cur));

		ap_cur->target = 1;
		ap_cur->wpa.state = 7;
		ap_cur->wpa.keyver = (uint8_t)(opt.amode & 0xFF);
		strcpy((char *) ap_cur->essid, "sorbo");
		strcpy((char *) ap_cur->bssid, "deadb");
		c_avl_insert(targets, ap_cur->bssid, ap_cur);

		goto __start;
	}

	// Cracking session is only for when one or more wordlists are used.
	// Airolib-ng not supported and stdin not allowed.
	if ((opt.dict == NULL || opt.no_stdin || db) && cracking_session)
	{
		fprintf(
			stderr,
			"Cannot save/restore cracking session when there is no wordlist,"
			" when using stdin or when using airolib-ng database.");
		goto exit_main;
	}

	progname = getVersion(
		"Aircrack-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC);

	if ((cracking_session && cracking_session->is_loaded
		 && cracking_session->argc - optind < 1)
		|| (!cracking_session && !_pmkid_16800 && argc - optind < 1))
	{
		if (nbarg == 1)
		{
		usage:
			if (progname == NULL)
				progname = getVersion(
					"Aircrack-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC);

			printf(usage,
				   progname,
				   (cpu_count > 1 || cpu_count == -1) ? "\n      -X         : "
														"disable  bruteforce   "
														"multithreading\n"
													  : "\n");

			// If the user requested help, exit directly.
			if (showhelp == 1) clean_exit(EXIT_SUCCESS);
		}

		// Missing parameters
		if (nbarg - optind == 0)
		{
			printf("No file to crack specified.\n");
		}
		if (nbarg > 1)
		{
			printf("\"%s --help\" for help.\n", argv[0]);
		}
		clean_exit(ret);
		return ret;
	}

	if (opt.amode >= 2 && opt.dict == NULL)
	{
		ret = missing_wordlist_dictionary(ap_cur);
		goto exit_main;
	}

	if ((!opt.essid_set && !opt.bssid_set) && (opt.is_quiet || opt.no_stdin))
	{
		printf("Please specify an ESSID or BSSID.\n");
		goto exit_main;
	}

	/* start one thread per input file */

	old = optind;
	n = nbarg - optind;
	id = 0;

	if (_pmkid_16800)
	{
		size_t remaining = strlen((char *) _pmkid_16800_str);

		if (remaining
			< H16800_PMKID_LEN + H16800_BSSID_LEN + H16800_STMAC_LEN + 4)
		{
			fprintf(stderr, "Input is too short!\n");
			goto exit_main;
		}

		opt.amode = 3;
		opt.bssid_set = 1;

		ap_cur = malloc(sizeof(*ap_cur));
		if (!ap_cur) err(1, "malloc()");

		memset(ap_cur, 0, sizeof(*ap_cur));

		// PMKID * BSSID * STMAC * ESSID
		// c2ea9449c142e84a0479041702526532*0012bf77162d*0021e924a5e7*574c414e2d373731363938 // WLAN-771698

		ap_cur->crypt = 4;
		ap_cur->target = 1;
		ap_cur->wpa.state = 5;
		ap_cur->wpa.keyver = (uint8_t)(opt.amode & 0xFF);

		hexStringToArray((char *) _pmkid_16800_str,
						 H16800_PMKID_LEN,
						 ap_cur->wpa.pmkid,
						 sizeof(ap_cur->wpa.pmkid));
		hexStringToArray((char *) _pmkid_16800_str + H16800_PMKID_LEN + 1,
						 H16800_BSSID_LEN,
						 ap_cur->bssid,
						 sizeof(ap_cur->bssid));
		hexStringToArray((char *) _pmkid_16800_str + H16800_PMKID_LEN + 1
							 + H16800_BSSID_LEN
							 + 1,
						 H16800_STMAC_LEN,
						 ap_cur->wpa.stmac,
						 sizeof(ap_cur->wpa.stmac));
		hexStringToArray(
			(char *) _pmkid_16800_str + H16800_PMKID_LEN + 1 + H16800_BSSID_LEN
				+ 1
				+ H16800_STMAC_LEN
				+ 1,
			(int) remaining - H16800_PMKID_LEN + 1 + H16800_BSSID_LEN + 1
				+ H16800_STMAC_LEN
				+ 1,
			ap_cur->essid,
			sizeof(ap_cur->essid));

		c_avl_insert(targets, ap_cur->bssid, ap_cur);

		goto __start;
	}

	if (!opt.bssid_set)
	{
		if (!opt.is_quiet)
		{
			printf("Reading packets, please wait...\n");
			fflush(stdout);
		}

		do
		{
			char * optind_arg = (restore_session && cracking_session)
									? cracking_session->argv[optind]
									: argv[optind];
			if (strcmp(optind_arg, "-") == 0) opt.no_stdin = 1;

			packet_reader_t * request
				= (packet_reader_t *) calloc(1, sizeof(packet_reader_t));
			ALLEGE(request != NULL);

			request->mode = PACKET_READER_CHECK_MODE;
			request->filename = optind_arg;

			if (pthread_create(&(tid[id]), NULL, &packet_reader_thread, request)
				!= 0)
			{
				perror("pthread_create failed");
				goto exit_main;
			}

			id++;
			if (id >= MAX_THREADS)
			{
				if (!opt.is_quiet)
					printf(
						"Only using the first %d files, ignoring the rest.\n",
						MAX_THREADS);
				break;
			}
		} while (++optind < nbarg);

		/* wait until each thread reaches EOF */

		for (i = 0; i < id; i++)
		{
			ALLEGE(pthread_join(tid[i], NULL) == 0);
			tid[i] = 0;
		}

		if (!opt.is_quiet && !opt.no_stdin)
		{
			erase_line(0);
			printf("Read %ld packets.\n\n", nb_pkt);
		}

		if (c_avl_size(access_points) == 0)
		{
			printf("No networks found, exiting.\n");
			goto exit_main;
		}

		if (cracking_session && restore_session)
		{
			// If cracking session present (and it is a restore), auto-load it
			int not_found = c_avl_get(
				access_points, cracking_session->bssid, (void **) &ap_cur);

			if (not_found)
			{
				fprintf(stderr, "Failed to find BSSID from restore session.\n");
				clean_exit(EXIT_FAILURE);
			}

			// Set BSSID
			memcpy(opt.bssid, ap_cur->bssid, ETHER_ADDR_LEN);
			opt.bssid_set = 1;

			// Set wordlist
			if (next_dict(cracking_session->wordlist_id))
			{
				fprintf(stderr,
						"Failed setting wordlist ID from restore session.\n");
				clean_exit(EXIT_FAILURE);
			}

			// Move into position in the wordlist
			if (fseeko(opt.dict, cracking_session->pos, SEEK_SET) != 0
				|| ftello(opt.dict) != cracking_session->pos)
			{
				fprintf(stderr,
						"Failed setting position in wordlist from "
						"restore session.\n");
				clean_exit(EXIT_FAILURE);
			}

			// Set amount of keys tried -> Done later
		}
		else if (!opt.essid_set && !opt.bssid_set)
		{
			/* ask the user which network is to be cracked */

			printf("   #  BSSID%14sESSID%21sEncryption\n\n", "", "");

			i = 1;

			void * key;
			c_avl_iterator_t * it = c_avl_get_iterator(access_points);
			while (c_avl_iterator_next(it, &key, (void **) &ap_cur) == 0)
			{
				memset(essid, 0, sizeof(essid));
				memcpy(essid, ap_cur->essid, ESSID_LENGTH);
				for (zz = 0; zz < ESSID_LENGTH; zz++)
				{
					if ((essid[zz] > 0 && essid[zz] < 32) || (essid[zz] > 126))
						essid[zz] = '?';
				}

				printf("%4d  %02X:%02X:%02X:%02X:%02X:%02X  %-24s  ",
					   i,
					   ap_cur->bssid[0],
					   ap_cur->bssid[1],
					   ap_cur->bssid[2],
					   ap_cur->bssid[3],
					   ap_cur->bssid[4],
					   ap_cur->bssid[5],
					   essid);

				if (ap_cur->eapol) printf("EAPOL+");

				switch (ap_cur->crypt)
				{
					case 0:
						printf("None (%d.%d.%d.%d)\n",
							   ap_cur->lanip[0],
							   ap_cur->lanip[1],
							   ap_cur->lanip[2],
							   ap_cur->lanip[3]);
						break;

					case 1:
						printf("No data - WEP or WPA\n");
						break;

					case 2:
						printf("WEP (%ld IVs)\n", ap_cur->nb_ivs_vague);
						break;

					case 3:
						printf("WPA (%d handshake%s)\n",
							   ap_cur->wpa.state == 7,
							   (ap_cur->wpa.pmkid[0] != 0x00 ? ", with PMKID"
															 : ""));
						break;

					default:
						printf("Unknown\n");
						break;
				}

				i++;
			}
			c_avl_iterator_destroy(it);
			it = NULL;

			printf("\n");

			if (c_avl_size(access_points) > 1)
			{
				do
				{
					printf("Index number of target network ? ");
					fflush(stdout);
					ret1 = 0;
					while (!ret1) ret1 = scanf("%127s", buf);

					if ((z = (int) strtol(buf, NULL, 10)) < 1) continue;

					i = 1;
					it = c_avl_get_iterator(access_points);
					while (c_avl_iterator_next(it, &key, (void **) &ap_cur) == 0
						   && i < z)
					{
						i++;
					}
					c_avl_iterator_destroy(it);
					it = NULL;
					if (i == z)
					{
						ap_cur->target = 1;
						c_avl_insert(targets, ap_cur->bssid, ap_cur);
					}
				} while (z < 0 || ap_cur == NULL);
			}
			else if (c_avl_size(access_points) == 1)
			{
				printf("Choosing first network as target.\n");
				it = c_avl_get_iterator(access_points);
				c_avl_iterator_next(it, &key, (void **) &ap_cur);
				c_avl_iterator_destroy(it);
				it = NULL;
				ALLEGE(ap_cur != NULL);
				ap_cur->target = 1;
				c_avl_insert(targets, ap_cur->bssid, ap_cur);
			}
			else
			{
				// no access points
			}

			printf("\n");

			ALLEGE(ap_cur != NULL);

			// Release memory of all APs we don't care about currently.
			ap_avl_release_unused(ap_cur);

			memcpy(opt.bssid, ap_cur->bssid, ETHER_ADDR_LEN);

			// Copy BSSID to the cracking session
			if (cracking_session && opt.dict != NULL)
			{
				memcpy(cracking_session->bssid, ap_cur->bssid, ETHER_ADDR_LEN);
			}

			/* Disable PTW if dictionary used in WEP */
			if (ap_cur->crypt == 2 && opt.dict != NULL)
			{
				opt.do_ptw = 0;
			}
		}

		optind = old;
		id = 0;
	}

	nb_prev_pkt = nb_pkt;
	nb_pkt = 0;
	nb_eof = 0;

	ALLEGE(signal(SIGINT, sighandler) != SIG_ERR);

	if (!opt.is_quiet)
	{
		printf("Reading packets, please wait...\n");
		fflush(stdout);
	}

	// NOTE: Reset internal logic used from CHECK, prior to full READ/PROCESS...
	if (ap_cur != NULL)
	{
		if (ap_cur->uiv_root != NULL)
		{
			uniqueiv_wipe(ap_cur->uiv_root);
			ap_cur->uiv_root = NULL;
		}

		ap_cur->nb_ivs = 0;
		ap_cur->ivbuf_size = 0;

		destroy(ap_cur->ivbuf, free);

		// Destroy WPA struct in all stations of the selected AP
		if (ap_cur->stations != NULL)
		{
			void * key = NULL;
			struct ST_info * st_tmp = NULL;

			while (c_avl_pick(ap_cur->stations, &key, (void **) &st_tmp) == 0)
			{
				INVARIANT(st_tmp != NULL);

				memset(&st_tmp->wpa, 0, sizeof(struct WPA_hdsk));
			}
		}
	}

	do
	{
		char * optind_arg
			= (restore_session) ? cracking_session->argv[optind] : argv[optind];
		if (strcmp(optind_arg, "-") == 0) opt.no_stdin = 1;

		packet_reader_t * request
			= (packet_reader_t *) calloc(1, sizeof(packet_reader_t));
		ALLEGE(request != NULL);

		request->mode = PACKET_READER_READ_MODE;
		request->filename = optind_arg;

		if (pthread_create(&(tid[id]), NULL, &packet_reader_thread, request)
			!= 0)
		{
			perror("pthread_create failed");
			goto exit_main;
		}

		id++;
		if (id >= MAX_THREADS) break;
	} while (++optind < nbarg);

	/* wait until threads re-read the original packets read in first pass */
	ALLEGE(pthread_mutex_lock(&mx_eof) == 0);
	if (!opt.bssid_set && !opt.essid_set)
	{
		while (nb_prev_pkt > nb_pkt && nb_eof != id)
			pthread_cond_wait(&cv_eof, &mx_eof);
	}
	else
	{
		while (nb_prev_pkt >= nb_pkt && nb_eof != id)
			pthread_cond_wait(&cv_eof, &mx_eof);
	}
	ALLEGE(pthread_mutex_unlock(&mx_eof) == 0);

	if (!opt.is_quiet && !opt.no_stdin)
	{
		erase_line(0);
		printf("Read %ld packets.\n\n", nb_pkt);
	}

	/* mark the targeted access point(s) */
	void * key;
	c_avl_iterator_t * it = c_avl_get_iterator(access_points);
	while (c_avl_iterator_next(it, &key, (void **) &ap_cur) == 0)
	{
		if (memcmp(opt.maddr, BROADCAST, ETHER_ADDR_LEN) == 0
			|| (opt.bssid_set
				&& !memcmp(opt.bssid, ap_cur->bssid, ETHER_ADDR_LEN))
			|| (opt.essid_set
				&& !memcmp(opt.essid, ap_cur->essid, ESSID_LENGTH)))
		{
			ap_cur->target = 1;
		}

		if (ap_cur->target)
		{
			c_avl_insert(targets, ap_cur->bssid, ap_cur);
		}
	}
	c_avl_iterator_destroy(it);
	it = NULL;

	printf("%d potential targets\n\n", c_avl_size(targets));
	ap_cur = get_first_target();

	if (ap_cur == NULL)
	{
		printf("No matching network found - check your %s.\n",
			   (opt.essid_set) ? "essid" : "bssid");

		goto exit_main;
	}

	if (ap_cur->crypt < 2)
	{
		switch (ap_cur->crypt)
		{
			case 0:
				printf("Target '%s' network doesn't seem encrypted.\n",
					   (char *) ap_cur->essid);
				break;

			default:
				printf("Got no data packets from target network!\n");
				break;
		}

		goto exit_main;
	}

	/* create the cracker<->master communication pipes */

	for (i = 0; i < opt.nbcpu; i++)
	{
		IGNORE_NZ(pipe(mc_pipe[i]));
		IGNORE_NZ(pipe(cm_pipe[i]));

		if (opt.amode <= 1 && opt.nbcpu > 1 && opt.do_brute && opt.do_mt_brute)
		{
			IGNORE_NZ(pipe(bf_pipe[i]));
			bf_nkeys[i] = 0;
		}
	}

__start:
	/* launch the attack */

	// Start cracking session
	if (cracking_session)
	{
		if (pthread_create(
				&cracking_session_tid, NULL, &session_save_thread, NULL)
			!= 0)
		{
			perror("pthread_create failed");
			goto exit_main;
		}
	}

	ALLEGE(pthread_mutex_lock(&mx_nb) == 0);
	// Set the amount of keys tried
	nb_tried = (cracking_session && restore_session)
				   ? cracking_session->nb_keys_tried
				   : 0;
	nb_kprev = 0;
	ALLEGE(pthread_mutex_unlock(&mx_nb) == 0);

	chrono(&t_begin, 1);
	chrono(&t_stats, 1);
	chrono(&t_kprev, 1);

	ALLEGE(signal(SIGWINCH, sighandler) != SIG_ERR);

	if (opt.amode == 1 || ap_cur->crypt == 2)
	{
		ret = perform_wep_crack(ap_cur);
	}

	if (opt.amode >= 2 || ap_cur->crypt >= 3)
	{
		ret = perform_wpa_crack(ap_cur);
	}

exit_main:

#if ((defined(__INTEL_COMPILER) || defined(__ICC)) && defined(DO_PGO_DUMP))
	_PGOPTI_Prof_Dump();
#endif
	if (!opt.is_quiet) printf("\n");

	fflush(stdout);

	clean_exit(ret);
	/* not reached */

	_exit(ret);
}
