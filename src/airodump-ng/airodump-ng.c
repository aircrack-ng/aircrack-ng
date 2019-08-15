/*
 *  pcap-compatible 802.11 packet sniffer
 *
 *  Copyright (C) 2006-2018 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
 *  Copyright (C) 2004, 2005 Christophe Devine
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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>

#ifndef TIOCGWINSZ
#include <sys/termios.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#define _WITH_DPRINTF
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <fcntl.h>
#include <pthread.h>
#include <termios.h>
#include <limits.h>

#include <sys/wait.h>

#ifdef HAVE_PCRE
#include <pcre.h>
#endif

#include "aircrack-ng/defs.h"
#include "aircrack-ng/version.h"
#include "aircrack-ng/support/pcap_local.h"
#include "aircrack-ng/ce-wep/uniqueiv.h"
#include "aircrack-ng/support/communications.h"
#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/osdep/channel.h"
#include "aircrack-ng/osdep/osdep.h"
#include "airodump-ng.h"
#include "dump_write.h"
#include "aircrack-ng/osdep/common.h"
#include "aircrack-ng/third-party/ieee80211.h"
#include "aircrack-ng/support/common.h"
#include "aircrack-ng/support/mcs_index_rates.h"
#include "aircrack-ng/utf8/verifyssid.h"
#include "aircrack-ng/tui/console.h"
#include "radiotap/radiotap.h"
#include "radiotap/radiotap_iter.h"
#include "strlcpy.h"
#include "ap_list.h"
#include "aircrack-ng/osdep/sta_list.h"

struct devices dev;
uint8_t h80211[4096] __attribute__((aligned(16)));
uint8_t tmpbuf[4096] __attribute__((aligned(16)));

static const unsigned char llcnull[] = {0, 0, 0, 0};

static char const unknown_manufacturer[] = "Unknown";

static const char * OUI_PATHS[]
	= {"./airodump-ng-oui.txt",
	   "/etc/aircrack-ng/airodump-ng-oui.txt",
	   "/usr/local/etc/aircrack-ng/airodump-ng-oui.txt",
	   "/usr/share/aircrack-ng/airodump-ng-oui.txt",
	   "/var/lib/misc/oui.txt",
	   "/usr/share/misc/oui.txt",
	   "/var/lib/ieee-data/oui.txt",
	   "/usr/share/ieee-data/oui.txt",
	   "/etc/manuf/oui.txt",
	   "/usr/share/wireshark/wireshark/manuf/oui.txt",
	   "/usr/share/wireshark/manuf/oui.txt",
	   NULL};

static int read_pkts = 0;
enum
{
    channel_list_sentinel = 0
};

static int abg_chans[] = 
{
    1,   7,   13,  2,   8,   3,   14,  9,   4,   10,  5,   11,  6,
	12,  36,  38,  40,  42,  44,  46,  48,  50,  52,  54,  56,  58,
	60,  62,  64,  100, 102, 104, 106, 108, 110, 112, 114, 116, 118,
	120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, 144, 149,
    151, 153, 155, 157, 159, 161, 165, 169, 173, channel_list_sentinel 
};

static int bg_chans[] = 
{ 
    1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12, channel_list_sentinel 
};

static int a_chans[] = 
{
    36,  38,  40,  42,  44,  46,  48,  50,  52,  54,  56,  58,
	60,  62,  64,  100, 102, 104, 106, 108, 110, 112, 114, 116,
	118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142,
    144, 149, 151, 153, 155, 157, 159, 161, 165, 169, 173, channel_list_sentinel 
};

struct detected_frequencies_st
{
    size_t count;
    size_t table_size;
    int * frequencies;
};

struct hopper_data_st
{
    int card;
    union
    {
        int frequency;
        int channel;
    } u;
};

static volatile int quitting = 0;
static volatile time_t quitting_event_ts = 0;

static void dump_sort(void);
static void dump_print(int ws_row, int ws_col, int if_num);
static char *
get_manufacturer(unsigned char mac0, unsigned char mac1, unsigned char mac2);
int is_filtered_essid(const uint8_t * essid);

/* bunch of global stuff */
struct communication_options opt;

TAILQ_HEAD(na_list_head, NA_info);

static struct local_options
{
	/* Two AP lists are maintained. The spare list is used when 
	 * sorting items. After sorting into the spare list, the index 
	 * is updated to point to the sorted list.
	 */
	struct ap_list_head ap_list[2];
	size_t current_ap_list_index;

	/* Two STA lists are maintained. The spare list is used when 
	 * sorting items. After sorting into the spare list, the index 
	 * is updated to point to the sorted list. 
	 */
	struct sta_list_head sta_list[2];
	size_t current_sta_list_index;

	struct na_list_head na_list;

    struct oui * manufacturer_list;

    mac_address prev_bssid;

	char ** f_essid;
	int f_essid_count;
#ifdef HAVE_PCRE
	pcre * f_essid_regex;
#endif
	char * dump_prefix;
	char * keyout;

	char * batt; /* Battery string       */

    int channel[MAX_CARDS]; /* current channel #    */
	int frequency[MAX_CARDS]; /* current frequency #    */

    int hopper_process_pipe[2];
    int signal_event_pipe[2]; 

	float gps_loc[8]; /* gps coordinates      */
	int save_gps; /* keep gps file flag   */
	int gps_valid_interval; /* how many seconds until we consider the GPS data invalid if we dont get new data */

	int * channels;

	int singlechan; /* channel hopping set 1*/
	int singlefreq; /* frequency hopping: 1 */
	int chswitch; /* switching method     */
	unsigned int f_encrypt; /* encryption filter    */
	int update_s; /* update delay in sec  */

	volatile int do_exit; /* interrupt flag       */
	struct winsize ws; /* console window size  */

	char * elapsed_time; /* capture time			*/

	int one_beacon; /* Record only 1 beacon?*/

	int * own_channels; /* custom channel list  */
	int * own_frequencies; /* custom frequency list  */

	int asso_client; /* only show associated clients */

	char * iwpriv;
	char * iwconfig;
	char * wlanctlng;

	mac_address wpa_bssid; /* the wpa handshake bssid   */
	char message[512];
	char decloak;

	char is_berlin; /* is the switch --berlin set? */
	int numaps; /* number of APs on the current list */
	int maxnumaps; /* maximum nubers of APs on the list */
	int maxaps; /* number of all APs found */
	int berlin; /* number of seconds it takes in berlin to fill the whole screen
				   with APs*/
	/*
	 * The name for this option may look quite strange, here is the story behind
	 * it:
	 * During the CCC2007, 10 august 2007, we (hirte, Mister_X) went to visit
	 * Berlin
	 * and couldn't resist to turn on airodump-ng to see how much access point
	 * we can
	 * get during the trip from Finowfurt to Berlin. When we were in Berlin, the
	 * number
	 * of AP increase really fast, so fast that it couldn't fit in a screen,
	 * even rotated;
	 * the list was really huge (we have a picture of that). The 2 minutes
	 * timeout
	 * (if the last packet seen is higher than 2 minutes, the AP isn't shown
	 * anymore)
	 * wasn't enough, so we decided to create a new option to change that
	 * timeout.
	 * We implemented this option in the highest tower (TV Tower) of Berlin,
	 * eating an ice.
	 */

	int show_ap;
	int show_sta;
	int show_ack;
	int hide_known;

	int hopfreq;

	char * s_iface; /* source interface to read from */
	FILE * f_cap_in;
	struct pcap_file_header pfh_in;
	int detect_anomaly; /* Detect WIPS protecting WEP in action */

	char * freqstring;
	int freqoption;
	int chanoption;
	int active_scan_sim; /* simulates an active scan, sending probe requests */

	/* Airodump-ng start time: for kismet netxml file */
	char * airodump_start_time;

	pthread_t input_tid;

    pthread_t gps_tid;
    int gps_thread_result;

	int sort_by;
	int sort_inv;
	int start_print_ap;
	int start_print_sta;
	struct AP_info * p_selected_ap;
	enum
	{
		selection_direction_down,
		selection_direction_up,
		selection_direction_no
	} en_selection_direction;
	int mark_cur_ap;
	int num_cards;
	int do_pause;
	int do_sort_always;

	pthread_mutex_t mx_print; /* lock write access to ap LL   */

    pthread_mutex_t mx_sort; /* lock write access to ap LL   */

	mac_address selected_bssid; /* bssid that is selected */

	u_int maxsize_essid_seen;
	int show_manufacturer;
	int show_uptime;
	int file_write_interval;
	u_int maxsize_wps_seen;
	int show_wps;
	struct tm gps_time; /* the timestamp from the gps data */
    char sys_name[256];  /* system name value for wifi scanner custom format */
    char loc_name[256];  /* location name value for wifi scanner custom format */
#ifdef CONFIG_LIBNL
	unsigned int htval;
#endif
	int background_mode;

	unsigned long min_pkts;

	int relative_time; /* read PCAP in psuedo-real-time */

    time_t filter_seconds;
    int file_reset_seconds;
} lopt;

static void resetSelection(void)
{
	lopt.sort_by = SORT_BY_POWER;
	lopt.sort_inv = 1;

	lopt.relative_time = 0;
	lopt.start_print_ap = 1;
	lopt.start_print_sta = 1;
	lopt.p_selected_ap = NULL;
	lopt.en_selection_direction = selection_direction_no;
	lopt.mark_cur_ap = 0;
	lopt.do_pause = 0;
	lopt.do_sort_always = 0;
    MAC_ADDRESS_CLEAR(&lopt.selected_bssid);
}

static void color_off(void)
{
	struct AP_info * ap_cur;

	TAILQ_FOREACH(ap_cur, &lopt.ap_list[lopt.current_ap_list_index], entry)
	{
		ap_cur->marked = 0;
		ap_cur->marked_color = 1;
	}

	textcolor_normal();
	textcolor_fg(TEXT_WHITE);
}

static void color_on(void)
{
	struct AP_info * ap_cur;
	int color = 1;

	color_off();

	TAILQ_FOREACH_REVERSE(ap_cur, &lopt.ap_list[lopt.current_ap_list_index], ap_list_head, entry)
	{
		struct ST_info * st_cur;

		if (ap_cur->nb_pkt < lopt.min_pkts
			|| time(NULL) - ap_cur->tlast > lopt.berlin)
		{
			continue;
		}

		if (ap_cur->security != 0 && lopt.f_encrypt != 0
			&& ((ap_cur->security & lopt.f_encrypt) == 0))
		{
			continue;
		}

		// Don't filter unassociated clients by ESSID
		if (!MAC_ADDRESS_IS_BROADCAST(&ap_cur->bssid)
			&& is_filtered_essid(ap_cur->essid))
		{
			continue;
		}

		TAILQ_FOREACH_REVERSE(st_cur, &lopt.sta_list[lopt.current_sta_list_index], sta_list_head, entry)
		{
			if (st_cur->base != ap_cur
				|| (time(NULL) - st_cur->tlast) > lopt.berlin)
			{
				continue;
			}

			if (MAC_ADDRESS_IS_BROADCAST(&ap_cur->bssid)
				&& lopt.asso_client)
			{
				continue;
			}

			if (color > TEXT_MAX_COLOR)
			{
				color++;
			}

			if (!ap_cur->marked)
			{
				ap_cur->marked = 1;
				if (MAC_ADDRESS_IS_BROADCAST(&ap_cur->bssid))
				{
					ap_cur->marked_color = 1;
				}
				else
				{
					ap_cur->marked_color = color++;
				}
			}
			else
			{
				ap_cur->marked_color = 1;
			}
		}
	}
}

static int
acquire_lock(pthread_mutex_t * const mutex)
{
    int const lock_result = pthread_mutex_lock(mutex);

    ALLEGE(lock_result == 0);

    return lock_result;
}

static int
release_lock(pthread_mutex_t * const mutex)
{
    int const unlock_result = pthread_mutex_unlock(mutex);

    ALLEGE(unlock_result == 0);

    return unlock_result;
}

static int
initialise_lock(pthread_mutex_t * const mutex)
{
    int const init_result = pthread_mutex_init(mutex, NULL);

    ALLEGE(init_result == 0);

    return init_result;
}

static int
acquire_sort_lock(struct local_options * const options)
{
    return acquire_lock(&options->mx_sort);
}

static int 
release_sort_lock(struct local_options * const options)
{
    return release_lock(&options->mx_sort);
}

static int initialise_sort_lock(struct local_options * const options)
{
    return initialise_lock(&options->mx_sort);
}

static int
acquire_print_lock(struct local_options * const options)
{
    return acquire_lock(&options->mx_print);
}

static int
release_print_lock(struct local_options * const options)
{
    return release_lock(&options->mx_print);
}

static int initialise_print_lock(struct local_options * const options)
{
    return initialise_lock(&options->mx_print);
}


static void input_thread(void * arg)
{
	UNUSED_PARAM(arg);

	while (lopt.do_exit == 0)
	{
		int keycode = 0;

		keycode = mygetch();

		if (keycode == KEY_q)
		{
			quitting_event_ts = time(NULL);

			if (++quitting > 1)
				lopt.do_exit = 1;
			else
				snprintf(
					lopt.message,
					sizeof(lopt.message),
					"][ Are you sure you want to quit? Press Q again to quit.");
		}

		if (keycode == KEY_o)
		{
			color_on();
			snprintf(lopt.message, sizeof(lopt.message), "][ color on");
		}

		if (keycode == KEY_p)
		{
			color_off();
			snprintf(lopt.message, sizeof(lopt.message), "][ color off");
		}

		if (keycode == KEY_s)
		{
			lopt.sort_by++;

			if (lopt.sort_by > MAX_SORT) lopt.sort_by = 0;

			switch (lopt.sort_by)
			{
				case SORT_BY_NOTHING:
					snprintf(lopt.message,
							 sizeof(lopt.message),
							 "][ sorting by first seen");
					break;
				case SORT_BY_BSSID:
					snprintf(lopt.message,
							 sizeof(lopt.message),
							 "][ sorting by bssid");
					break;
				case SORT_BY_POWER:
					snprintf(lopt.message,
							 sizeof(lopt.message),
							 "][ sorting by power level");
					break;
				case SORT_BY_BEACON:
					snprintf(lopt.message,
							 sizeof(lopt.message),
							 "][ sorting by beacon number");
					break;
				case SORT_BY_DATA:
					snprintf(lopt.message,
							 sizeof(lopt.message),
							 "][ sorting by number of data packets");
					break;
				case SORT_BY_PRATE:
					snprintf(lopt.message,
							 sizeof(lopt.message),
							 "][ sorting by packet rate");
					break;
				case SORT_BY_CHAN:
					snprintf(lopt.message,
							 sizeof(lopt.message),
							 "][ sorting by channel");
					break;
				case SORT_BY_MBIT:
					snprintf(lopt.message,
							 sizeof(lopt.message),
							 "][ sorting by max data rate");
					break;
				case SORT_BY_ENC:
					snprintf(lopt.message,
							 sizeof(lopt.message),
							 "][ sorting by encryption");
					break;
				case SORT_BY_CIPHER:
					snprintf(lopt.message,
							 sizeof(lopt.message),
							 "][ sorting by cipher");
					break;
				case SORT_BY_AUTH:
					snprintf(lopt.message,
							 sizeof(lopt.message),
							 "][ sorting by authentication");
					break;
				case SORT_BY_ESSID:
					snprintf(lopt.message,
							 sizeof(lopt.message),
							 "][ sorting by ESSID");
					break;
				default:
					break;
			}

            acquire_sort_lock(&lopt);

			dump_sort();

			release_sort_lock(&lopt);
		}

		if (keycode == KEY_SPACE)
		{
			lopt.do_pause = !lopt.do_pause;
			if (lopt.do_pause)
			{
				snprintf(
					lopt.message, sizeof(lopt.message), "][ paused output");

                acquire_print_lock(&lopt);
				dump_print(lopt.ws.ws_row, lopt.ws.ws_col, lopt.num_cards);
                release_print_lock(&lopt);
			}
			else
				snprintf(
					lopt.message, sizeof(lopt.message), "][ resumed output");
		}

		if (keycode == KEY_r)
		{
			lopt.do_sort_always = (lopt.do_sort_always + 1) % 2;

			if (lopt.do_sort_always)
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ realtime sorting activated");
			else
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ realtime sorting deactivated");
		}

		if (keycode == KEY_m)
		{
			lopt.mark_cur_ap = 1;
		}

		if (keycode == KEY_ARROW_DOWN)
		{
			if (lopt.p_selected_ap && TAILQ_PREV(lopt.p_selected_ap, ap_list_head, entry) != NULL)
			{
				lopt.p_selected_ap = TAILQ_PREV(lopt.p_selected_ap, ap_list_head, entry);
				lopt.en_selection_direction = selection_direction_down;
			}
		}

		if (keycode == KEY_ARROW_UP)
		{
			if (lopt.p_selected_ap && TAILQ_NEXT(lopt.p_selected_ap, entry) != NULL)
			{
				lopt.p_selected_ap = TAILQ_NEXT(lopt.p_selected_ap, entry);
				lopt.en_selection_direction = selection_direction_up;
			}
		}

		if (keycode == KEY_i)
		{
			lopt.sort_inv *= -1;
			if (lopt.sort_inv < 0)
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ inverted sorting order");
			else
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ normal sorting order");
		}

		if (keycode == KEY_TAB)
		{
			if (lopt.p_selected_ap == NULL)
			{
				lopt.p_selected_ap = TAILQ_LAST(&lopt.ap_list[lopt.current_ap_list_index], ap_list_head);
				lopt.en_selection_direction = selection_direction_down;
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ enabled AP selection");
				lopt.sort_by = SORT_BY_NOTHING;
			}
			else
			{
				lopt.en_selection_direction = selection_direction_no;
				lopt.p_selected_ap = NULL;
				lopt.sort_by = SORT_BY_NOTHING;
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ disabled selection");
			}
		}

		if (keycode == KEY_a)
		{
			if (lopt.show_ap == 1 && lopt.show_sta == 1 && lopt.show_ack == 0)
			{
				lopt.show_ap = 1;
				lopt.show_sta = 1;
				lopt.show_ack = 1;
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ display ap+sta+ack");
			}
			else if (lopt.show_ap == 1 && lopt.show_sta == 1
					 && lopt.show_ack == 1)
			{
				lopt.show_ap = 1;
				lopt.show_sta = 0;
				lopt.show_ack = 0;
				snprintf(
					lopt.message, sizeof(lopt.message), "][ display ap only");
			}
			else if (lopt.show_ap == 1 && lopt.show_sta == 0
					 && lopt.show_ack == 0)
			{
				lopt.show_ap = 0;
				lopt.show_sta = 1;
				lopt.show_ack = 0;
				snprintf(
					lopt.message, sizeof(lopt.message), "][ display sta only");
			}
			else if (lopt.show_ap == 0 && lopt.show_sta == 1
					 && lopt.show_ack == 0)
			{
				lopt.show_ap = 1;
				lopt.show_sta = 1;
				lopt.show_ack = 0;
				snprintf(
					lopt.message, sizeof(lopt.message), "][ display ap+sta");
			}
		}

		if (keycode == KEY_d)
		{
			resetSelection();
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ reset selection to default");
		}

		if (lopt.do_exit == 0 && !lopt.do_pause)
		{
            acquire_print_lock(&lopt);
            dump_print(lopt.ws.ws_row, lopt.ws.ws_col, lopt.num_cards);
            release_print_lock(&lopt);
        }
	}
}

static FILE * open_oui_file(void)
{
	FILE * fp = NULL;

	for (size_t i = 0; OUI_PATHS[i] != NULL; i++)
	{
		fp = fopen(OUI_PATHS[i], "r");
		if (fp != NULL)
		{
			break;
		}
	}

	return fp;
}

static void oui_list_free(struct oui * * const oui_list)
{
    struct oui * oui = *oui_list;

    *oui_list = NULL;

    while (oui != NULL)
    {
        struct oui * const next = oui->next;

        free(oui->manufacturer);
        free(oui);

        oui = next;
    }
}

static struct oui * load_oui_file(void)
{
	FILE * fp;
	char buffer[BUFSIZ];
    struct oui * oui_head = NULL;
    struct oui * * oui_next = &oui_head; 


	fp = open_oui_file();
	if (fp == NULL)
	{
		goto done;
	}

	while (fgets(buffer, sizeof(buffer), fp) != NULL)
	{
        unsigned char a[2] = { 0 };
        unsigned char b[2] = { 0 };
        unsigned char c[2] = { 0 };

        if (strstr(buffer, "(hex)") == NULL)
        {
            continue;
        }

		// Remove leading/trailing whitespaces.
		trim(buffer);
		if (sscanf(buffer, "%2c-%2c-%2c", (char *) a, (char *) b, (char *) c)
			== 3)
		{
            struct oui * const oui_ptr = calloc(1, sizeof *oui_ptr);

            if (oui_ptr == NULL)
            {
                oui_list_free(&oui_head);
                perror("oui_alloc failed");
                goto done;
			}

			snprintf(oui_ptr->id,
					 sizeof(oui_ptr->id),
					 "%c%c:%c%c:%c%c",
					 a[0],
					 a[1],
					 b[0],
					 b[1],
					 c[0],
					 c[1]);

            oui_ptr->manufacturer = 
                get_manufacturer_from_string(buffer);

            if (oui_ptr->manufacturer == NULL)
			{
                oui_ptr->manufacturer = strdup(unknown_manufacturer);
			}

            *oui_next = oui_ptr;
            oui_next = &oui_ptr->next;
        }
	}

done:
    if (fp != NULL)
    {
        fclose(fp);
    }

	return oui_head;
}

static const char usage[] =

	"\n"
	"  %s - (C) 2006-2018 Thomas d\'Otreppe\n"
	"  https://www.aircrack-ng.org\n"
	"\n"
	"  usage: airodump-ng <options> <interface>[,<interface>,...]\n"
	"\n"
	"  Options:\n"
	"      --ivs                 : Save only captured IVs\n"
	"      --gpsd                : Use GPSd\n"
	"      --write      <prefix> : Dump file prefix\n"
	"      -w                    : same as --write \n"
	"      --beacons             : Record all beacons in dump file\n"
	"      --update       <secs> : Display update delay in seconds\n"
	"      --showack             : Prints ack/cts/rts statistics\n"
	"      -h                    : Hides known stations for --showack\n"
	"      -f            <msecs> : Time in ms between hopping channels\n"
	"      --berlin       <secs> : Time before removing the AP/client\n"
	"                              from the screen when no more packets\n"
	"                              are received (Default: 120 seconds)\n"
	"      -r             <file> : Read packets from that file\n"
	"      -T                    : While reading packets from a file,\n"
	"                              simulate the arrival rate of them\n"
	"                              as if they were \"live\".\n"
	"      -x            <msecs> : Active Scanning Simulation\n"
	"      --manufacturer        : Display manufacturer from IEEE OUI list\n"
	"      --uptime              : Display AP Uptime from Beacon Timestamp\n"
	"      --wps                 : Display WPS information (if any)\n"
	"      --output-format\n"
	"                  <formats> : Output format. Possible values:\n"
    "                              pcap, ivs, csv, gps, kismet, netxml, wifi_scanner"
    ", logcsv\n"
    "      --sys-name            : Unique System Name\n"
    "      --loc-name            : Unique Location Name\n"
    "      --filter-seconds      : Filter time (seconds)\n"
    "      --file-reset-minutes  : File reset time (minutes)\n"
    "      --ignore-negative-one : Removes the message that says\n"
	"                              fixed channel <interface>: -1\n"
	"      --write-interval\n"
	"                  <seconds> : Output file(s) write interval in seconds\n"
	"      --background <enable> : Override background detection.\n"
	"      -n              <int> : Minimum AP packets recv'd before\n"
	"                              for displaying it\n"
	"\n"
	"  Filter options:\n"
	"      --encrypt   <suite>   : Filter APs by cipher suite\n"
	"      --netmask <netmask>   : Filter APs by mask\n"
	"      --bssid     <bssid>   : Filter APs by BSSID\n"
	"      --essid     <essid>   : Filter APs by ESSID\n"
#ifdef HAVE_PCRE
	"      --essid-regex <regex> : Filter APs by ESSID using a regular\n"
	"                              expression\n"
#endif
	"      -a                    : Filter unassociated clients\n"
	"\n"
	"  By default, airodump-ng hops on 2.4GHz channels.\n"
	"  You can make it capture on other/specific channel(s) by using:\n"
	"      --ht20                : Set channel to HT20 (802.11n)\n"
	"      --ht40-               : Set channel to HT40- (802.11n)\n"
	"      --ht40+               : Set channel to HT40+ (802.11n)\n"
	"      --channel <channels>  : Capture on specific channels\n"
	"      --band <abg>          : Band on which airodump-ng should hop\n"
	"      -C    <frequencies>   : Uses these frequencies in MHz to hop\n"
	"      --cswitch  <method>   : Set channel switching method\n"
	"                    0       : FIFO (default)\n"
	"                    1       : Round Robin\n"
	"                    2       : Hop on last\n"
	"      -s                    : same as --cswitch\n"
	"\n"
	"      --help                : Displays this usage screen\n"
	"\n";

static void airodump_usage(void)
{
	char * const l_usage = getVersion(
		"Airodump-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC);
	printf(usage, l_usage);
	free(l_usage);
}

static int is_filtered_netmask(mac_address const * const bssid)
{
	REQUIRE(bssid != NULL);

    mac_address mac1;
    mac_address mac2;

    for (size_t i = 0; i < sizeof mac1; i++)
	{
		mac1.addr[i] = bssid->addr[i] & opt.f_netmask[i];
		mac2.addr[i] = opt.f_bssid.addr[i] & opt.f_netmask[i];
	}

    bool const is_filtered = !MAC_ADDRESS_EQUAL(&mac1, &mac2);

	return is_filtered;
}

int is_filtered_essid(const uint8_t * essid)
{
	REQUIRE(essid != NULL);

	int ret = 0;
	int i;

	if (lopt.f_essid)
	{
		for (i = 0; i < lopt.f_essid_count; i++)
		{
			if (strncmp((char *) essid, lopt.f_essid[i], ESSID_LENGTH) == 0)
			{
				return (0);
			}
		}

		ret = 1;
	}

#ifdef HAVE_PCRE
	if (lopt.f_essid_regex)
	{
		return pcre_exec(lopt.f_essid_regex,
						 NULL,
						 (char *) essid,
						 (int) strnlen((char *) essid, ESSID_LENGTH),
						 0,
						 0,
						 NULL,
						 0)
			   < 0;
	}
#endif

	return (ret);
}

static void update_rx_quality(void)
{
	unsigned long time_diff, capt_time, miss_time;
	struct timeval cur_time;

	gettimeofday(&cur_time, NULL);

	/* access points */
	struct AP_info * ap_cur;

	TAILQ_FOREACH(ap_cur, &lopt.ap_list[lopt.current_ap_list_index], entry)
	{
		time_diff = 1000000UL * (cur_time.tv_sec - ap_cur->ftimer.tv_sec)
					+ (cur_time.tv_usec - ap_cur->ftimer.tv_usec);

		/* update every `QLT_TIME`seconds if the rate is low, or every 500ms
		 * otherwise */
		if ((ap_cur->fcapt >= QLT_COUNT && time_diff > 500000)
			|| time_diff > (QLT_TIME * 1000000))
		{
			/* at least one frame captured */
			if (ap_cur->fcapt > 1)
			{
				capt_time
					= (1000000UL * (ap_cur->ftimel.tv_sec
									- ap_cur->ftimef.tv_sec) // time between
					   // first and last
					   // captured frame
					   + (ap_cur->ftimel.tv_usec - ap_cur->ftimef.tv_usec));

				miss_time
					= (1000000UL * (ap_cur->ftimef.tv_sec
									- ap_cur->ftimer.tv_sec) // time between
					   // timer reset and
					   // first frame
					   + (ap_cur->ftimef.tv_usec - ap_cur->ftimer.tv_usec))
					  + (1000000UL * (cur_time.tv_sec
									  - ap_cur->ftimel.tv_sec) // time between
						 // last frame and
						 // this moment
						 + (cur_time.tv_usec - ap_cur->ftimel.tv_usec));

				// number of frames missed at the time where no frames were
				// captured; extrapolated by assuming a constant framerate
				if (capt_time > 0 && miss_time > 200000)
				{
					int const missed_frames = 
						(int) (((float) miss_time / (float) capt_time)
								 * ((float) ap_cur->fcapt
									+ (float) ap_cur->fmiss));
					ap_cur->fmiss += missed_frames;
				}

				ap_cur->rx_quality
					= (int) (((float) ap_cur->fcapt
							  / ((float) ap_cur->fcapt + (float) ap_cur->fmiss))
							 *
#if defined(__x86_64__) && defined(__CYGWIN__)
							 (0.0f + 100));
#else
							 100.0f);
#endif
			}
			else
				ap_cur->rx_quality = 0; /* no packets -> zero quality */

			/* normalize, in case the seq numbers are not iterating */
			if (ap_cur->rx_quality > 100)
			{
				ap_cur->rx_quality = 100;
			}
			if (ap_cur->rx_quality < 0)
			{
				ap_cur->rx_quality = 0;
			}

			/* reset variables */
			ap_cur->fcapt = 0;
			ap_cur->fmiss = 0;
			gettimeofday(&ap_cur->ftimer, NULL);
		}
	}

	/* stations */
	struct ST_info * st_cur;

	TAILQ_FOREACH(st_cur, &lopt.sta_list[lopt.current_sta_list_index], entry)
	{
		time_diff = 1000000UL * (cur_time.tv_sec - st_cur->ftimer.tv_sec)
					+ (cur_time.tv_usec - st_cur->ftimer.tv_usec);

		if (time_diff > 10000000)
		{
			st_cur->missed = 0;
			gettimeofday(&(st_cur->ftimer), NULL);
		}
	}
}

static int update_dataps(void)
{
	struct timeval tv;
	struct AP_info * ap_cur;
	struct NA_info * na_cur;
	int ps;
	unsigned long diff;
	float pause;
	time_t sec;
	suseconds_t usec;

	gettimeofday(&tv, NULL);

	TAILQ_FOREACH_REVERSE(ap_cur, &lopt.ap_list[lopt.current_ap_list_index], ap_list_head, entry)
	{
		sec = (tv.tv_sec - ap_cur->tv.tv_sec);
		usec = (tv.tv_usec - ap_cur->tv.tv_usec);
#if defined(__x86_64__) && defined(__CYGWIN__)
		pause = (((sec * (0.0f + 1000000.0f) + usec)) / ((0.0f + 1000000.0f)));
#else
		pause = (sec * 1000000.0f + usec) / (1000000.0f);
#endif
		if (pause > 2.0f)
		{
			diff = ap_cur->nb_data - ap_cur->nb_data_old;
			ps = (int) (((float) diff) / pause);
			ap_cur->nb_dataps = ps;
			ap_cur->nb_data_old = ap_cur->nb_data;
			gettimeofday(&(ap_cur->tv), NULL);
		}
	}

	TAILQ_FOREACH(na_cur, &lopt.na_list, entry)
	{
		sec = (tv.tv_sec - na_cur->tv.tv_sec);
		usec = (tv.tv_usec - na_cur->tv.tv_usec);
#if defined(__x86_64__) && defined(__CYGWIN__)
		pause = (((sec * (0.0f + 1000000.0f) + usec)) / ((0.0f + 1000000.0f)));
#else
		pause = (sec * 1000000.0f + usec) / (1000000.0f);
#endif
		if (pause > 2.0f)
		{
			diff = (unsigned long) (na_cur->ack - na_cur->ack_old);
			ps = (int) (((float) diff) / pause);
			na_cur->ackps = ps;
			na_cur->ack_old = na_cur->ack;
			gettimeofday(&(na_cur->tv), NULL);
		}
	}

	return (0);
}

static void packet_buf_free(struct pkt_buf * const pkt_buf)
{
	free(pkt_buf->packet);
	free(pkt_buf);
}

static int packet_list_free(struct pkt_list_head * const pkt_list)
{
	while (TAILQ_FIRST(pkt_list) != NULL)
	{
		struct pkt_buf * const pkt_buf = TAILQ_FIRST(pkt_list);

		TAILQ_REMOVE(pkt_list, pkt_buf, entry);

		packet_buf_free(pkt_buf);
	}

	return 0;
}

static void ap_purge_old_packets(
	struct AP_info * const ap_cur, 
	struct timeval const * const current_time,
	unsigned long const age_limit_millisecs)
{
	struct pkt_buf * pkt_buf;
	struct pkt_buf * temp; 
	bool found_old_packet = false;

	TAILQ_FOREACH_SAFE(pkt_buf, &ap_cur->pkt_list, entry, temp)
	{
		if (!found_old_packet)
		{
			unsigned long const time_diff =
			(((current_time->tv_sec - (pkt_buf->ctime.tv_sec)) * 1000000UL)
				 + (current_time->tv_usec - (pkt_buf->ctime.tv_usec)))
				/ 1000;

			if (time_diff > age_limit_millisecs)
			{
				found_old_packet = true;
			}
		}

		if (found_old_packet)
		{
			TAILQ_REMOVE(&ap_cur->pkt_list, pkt_buf, entry);

			packet_buf_free(pkt_buf);
		}
	}

}

static void aps_purge_old_packets(
	struct local_options * const options,
	unsigned long const age_limit_millisecs)
{
	struct timeval current_time;

	gettimeofday(&current_time, NULL);

	struct AP_info * ap_cur;

	TAILQ_FOREACH(ap_cur, &options->ap_list[options->current_ap_list_index], entry)
	{
		ap_purge_old_packets(ap_cur, &current_time, age_limit_millisecs);
	}
}

static int
list_add_packet(struct pkt_list_head * const pkt_list, int const length, unsigned char * packet)
{
	struct pkt_buf * new_pkt_buf;

	if (length <= 0) return 1;
	if (packet == NULL) return 1;

    new_pkt_buf = calloc(1, sizeof *new_pkt_buf);
    if (new_pkt_buf == NULL)
    {
        return 1;
    }

    new_pkt_buf->packet = malloc((size_t)length);
    if (new_pkt_buf->packet == NULL)
    {
        free(new_pkt_buf);
        return 1;
    }

    memcpy(new_pkt_buf->packet, packet, (size_t)length);
    new_pkt_buf->length = (uint16_t)length;

    gettimeofday(&new_pkt_buf->ctime, NULL);

	TAILQ_INSERT_HEAD(pkt_list, new_pkt_buf, entry);

	return 0;
}

/*
 * Check if the same IV was used if the first two bytes were the same.
 * If they are not identical, it would complain.
 * The reason is that the first two bytes unencrypted are 'aa'
 * so with the same IV it should always be encrypted to the same thing.
 */
static int
list_check_decloak(struct pkt_list_head * const pkt_list, int length, const uint8_t * packet)
{
	struct pkt_buf * next;
	int i, correct;

	if (packet == NULL)
	{
		return 1;
	}

	if (length <= 0)
	{
		return 1;
	}

	TAILQ_FOREACH(next, pkt_list, entry)
	{
		if ((next->length + 4) == length)
		{
			correct = 1;
			// check for 4 bytes added after the end
			for (i = 28; i < length - 28; i++) // check everything (in the old
			// packet) after the IV
			// (including crc32 at the end)
			{
				if (next->packet[i] != packet[i])
				{
					correct = 0;
					break;
				}
			}
			if (!correct)
			{
				correct = 1;
				// check for 4 bytes added at the beginning
				for (i = 28; i < length - 28; i++) // check everything (in the
				// old packet) after the IV
				// (including crc32 at the
				// end)
				{
					if (next->packet[i] != packet[4 + i])
					{
						correct = 0;
						break;
					}
				}
			}
			if (correct == 1)
			{
				return 0; // found decloaking!
			}
		}
	}

	return 1; // didn't find decloak
}

static void na_info_free(struct NA_info * const na_cur)
{
	if (na_cur != NULL)
	{
		TAILQ_REMOVE(&lopt.na_list, na_cur, entry);
		free(na_cur);
	}
}

static void na_info_list_free(struct na_list_head * const list_head)
{
	struct NA_info * na_cur;
	struct NA_info * na_temp;

	TAILQ_FOREACH_SAFE(na_cur, list_head, entry, na_temp)
	{
		na_info_free(na_cur);
	}

	return;
}

static struct NA_info * na_info_lookup(
	struct na_list_head * const list, 
	mac_address const * const mac)
{
	struct NA_info * na_cur;

	TAILQ_FOREACH(na_cur, list, entry)
	{
		if (MAC_ADDRESS_EQUAL(&na_cur->namac, mac))
		{
			break;
		}
	}

	return na_cur;
}

static int remove_namac(mac_address const * const mac)
{
	struct NA_info * const na_cur = na_info_lookup(&lopt.na_list, mac);

	/* If it's known, remove it */
	na_info_free(na_cur);

	return 0;
}

static struct AP_info * ap_info_lookup(
	struct ap_list_head * ap_list, 
	mac_address const * const mac)
{
	struct AP_info * ap_cur;

	TAILQ_FOREACH(ap_cur, ap_list, entry)
	{
		if (MAC_ADDRESS_EQUAL(&ap_cur->bssid, mac))
		{
			break;
		}
	}

	return ap_cur;
}

static struct ST_info * sta_info_lookup(
	struct sta_list_head * const sta_list, 
	mac_address const * const mac)
{
	struct ST_info * st_cur;

	TAILQ_FOREACH(st_cur, sta_list, entry)
	{
		if (MAC_ADDRESS_EQUAL(&st_cur->stmac, mac))
		{
			break;
		}
	}

	return st_cur;
}

// NOTE(jbenden): This is also in ivstools.c
static int dump_add_packet(
	unsigned char * h80211,
	size_t const caplen,
	struct rx_info * ri,
	int cardnum)
{
	REQUIRE(h80211 != NULL);

	int seq, msd, offset, clen, o;
	size_t i;
	size_t n;
	size_t dlen;
	unsigned z;
	int type, length, numuni = 0;
	size_t numauth = 0;
	struct pcap_pkthdr pkh;
	struct timeval tv;
	struct ivs2_pkthdr ivs2;
	unsigned char *p, *org_p, c;
    mac_address bssid;
	mac_address stmac;
    mac_address namac;
    unsigned char clear[2048] = { 0 };
    int weight[16] = { 0 };
	int num_xor = 0;

	struct AP_info * ap_cur = NULL;
	struct ST_info * st_cur = NULL; 

	MAC_ADDRESS_CLEAR(&bssid);
	MAC_ADDRESS_CLEAR(&stmac);
	MAC_ADDRESS_CLEAR(&namac); 

	/* skip all non probe response frames in active scanning simulation mode */
	if (lopt.active_scan_sim > 0 && h80211[0] != 0x50)
	{
		return (0);
	}

	/* Skip packets smaller than a 802.11 header. */
	if (caplen < (int)sizeof(struct ieee80211_frame))
	{
		goto write_packet;
	}

	/* skip (uninteresting) control frames */

	if ((h80211[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_CTL)
		goto write_packet;

	/* if it's a LLC null packet, just forget it (may change in the future) */

	if (caplen > 28)
	{
		if (memcmp(h80211 + 24, llcnull, 4) == 0) return (0);
	}

	/* grab the sequence number */
	seq = ((h80211[22] >> 4) + (h80211[23] << 4));

	/* locate the access point's MAC address */

	switch (h80211[1] & IEEE80211_FC1_DIR_MASK)
	{
		case IEEE80211_FC1_DIR_NODS:
			MAC_ADDRESS_COPY(&bssid, (mac_address *)(h80211 + 16));
			break; // Adhoc
		case IEEE80211_FC1_DIR_TODS:
			MAC_ADDRESS_COPY(&bssid, (mac_address *)(h80211 + 4));
			break; // ToDS
		case IEEE80211_FC1_DIR_FROMDS:
			MAC_ADDRESS_COPY(&bssid, (mac_address *)(h80211 + 10));
			break; // FromDS
		case IEEE80211_FC1_DIR_DSTODS:
			MAC_ADDRESS_COPY(&bssid, (mac_address *)(h80211 + 10));
			break; // WDS -> Transmitter taken as BSSID
		default:
			abort();
	}

	if (!MAC_ADDRESS_IS_EMPTY(&opt.f_bssid))
	{
		if (memcmp(opt.f_netmask, NULL_MAC, 6) != 0)
		{
			if (is_filtered_netmask(&bssid))
			{
				return (1);
			}
		}
		else
		{
			if (!MAC_ADDRESS_EQUAL(&opt.f_bssid, &bssid))
			{
				return (1);
			}
		}
	}

	/* update our chained list of access points */
	ap_cur = ap_info_lookup(&lopt.ap_list[lopt.current_ap_list_index], &bssid);

	/* If it's a new access point, add it */
	if (ap_cur == NULL)
	{
        ap_cur = calloc(1, sizeof(*ap_cur));
		if (ap_cur == NULL)
		{
			perror("calloc failed");
			return (1);
		}

		/* if mac is listed as unknown, remove it */
		remove_namac(&bssid);

		MAC_ADDRESS_COPY(&ap_cur->bssid, &bssid);
		if (ap_cur->manuf == NULL)
		{
			ap_cur->manuf = get_manufacturer(
				ap_cur->bssid.addr[0], ap_cur->bssid.addr[1], ap_cur->bssid.addr[2]);
		}

		ap_cur->nb_pkt = 0;

		ap_cur->tinit = time(NULL);
		ap_cur->tlast = time(NULL);
        ap_cur->time_printed = 0; 

		ap_cur->avg_power = -1;
		ap_cur->best_power = -1;
		ap_cur->power_index = -1;

		for (i = 0; i < NB_PWR; i++)
		{
			ap_cur->power_lvl[i] = -1;
		}

		ap_cur->channel = -1;
        ap_cur->old_channel = -1;
        ap_cur->max_speed = -1;
		ap_cur->security = 0;

		ap_cur->ivbuf = NULL;
		ap_cur->ivbuf_size = 0;
		ap_cur->uiv_root = uniqueiv_init();

		ap_cur->nb_data = 0;
		ap_cur->nb_dataps = 0;
		ap_cur->nb_data_old = 0;
		gettimeofday(&(ap_cur->tv), NULL);

		ap_cur->dict_started = 0;

		ap_cur->key = NULL;

		ap_cur->nb_bcn = 0;

		ap_cur->rx_quality = 0;
		ap_cur->fcapt = 0;
		ap_cur->fmiss = 0;
		ap_cur->last_seq = 0;
		gettimeofday(&(ap_cur->ftimef), NULL);
		gettimeofday(&(ap_cur->ftimel), NULL);
		gettimeofday(&(ap_cur->ftimer), NULL);

		ap_cur->ssid_length = 0;
		ap_cur->essid_stored = 0;
        memset(ap_cur->essid, 0, sizeof ap_cur->essid);
		ap_cur->timestamp = 0;

		ap_cur->decloak_detect = lopt.decloak;
		ap_cur->is_decloak = 0;

		TAILQ_INIT(&ap_cur->pkt_list);

		ap_cur->marked = 0;
		ap_cur->marked_color = 1;

		ap_cur->data_root = NULL;
		ap_cur->EAP_detected = 0;
		memcpy(ap_cur->gps_loc_min, lopt.gps_loc, sizeof(float) * 5); //-V512
		memcpy(ap_cur->gps_loc_max, lopt.gps_loc, sizeof(float) * 5); //-V512
		memcpy(ap_cur->gps_loc_best, lopt.gps_loc, sizeof(float) * 5); //-V512

		/* 802.11n and ac */
		ap_cur->channel_width = CHANNEL_22MHZ; // 20MHz by default
        memset(ap_cur->standard, 0, sizeof ap_cur->standard);

		ap_cur->n_channel.sec_channel = -1;
		ap_cur->n_channel.short_gi_20 = 0;
		ap_cur->n_channel.short_gi_40 = 0;
		ap_cur->n_channel.any_chan_width = 0;
		ap_cur->n_channel.mcs_index = -1;

		ap_cur->ac_channel.center_sgmt[0] = 0;
		ap_cur->ac_channel.center_sgmt[1] = 0;
		ap_cur->ac_channel.mu_mimo = 0;
		ap_cur->ac_channel.short_gi_80 = 0;
		ap_cur->ac_channel.short_gi_160 = 0;
		ap_cur->ac_channel.split_chan = 0;
		ap_cur->ac_channel.mhz_160_chan = 0;
		ap_cur->ac_channel.wave_2 = 0;
        memset(ap_cur->ac_channel.mcs_index, 0, sizeof ap_cur->ac_channel.mcs_index);

		TAILQ_INSERT_TAIL(&lopt.ap_list[lopt.current_ap_list_index], ap_cur, entry);
	}

	/* update the last time seen */

	ap_cur->tlast = time(NULL);

	/* only update power if packets comes from
	 * the AP: either type == mgmt and SA == BSSID,
	 * or FromDS == 1 and ToDS == 0 */

	if (((h80211[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_NODS
		 && MAC_ADDRESS_EQUAL((mac_address *)(h80211 + 10), &bssid))
		|| ((h80211[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_FROMDS))
	{
		ap_cur->power_index = (ap_cur->power_index + 1) % NB_PWR;
		ap_cur->power_lvl[ap_cur->power_index] = ri->ri_power;

		// Moving exponential average
		// ma_new = alpha * new_sample + (1-alpha) * ma_old;
		ap_cur->avg_power
			= (int) (0.99f * ri->ri_power + (1.f - 0.99f) * ap_cur->avg_power);

		if (ap_cur->avg_power > ap_cur->best_power)
		{
			ap_cur->best_power = ap_cur->avg_power;
			memcpy(ap_cur->gps_loc_best, //-V512
				   lopt.gps_loc,
				   sizeof(float) * 5);
		}

		/* every packet in here comes from the AP */

		if (lopt.gps_loc[0] > ap_cur->gps_loc_max[0])
			ap_cur->gps_loc_max[0] = lopt.gps_loc[0];
		if (lopt.gps_loc[1] > ap_cur->gps_loc_max[1])
			ap_cur->gps_loc_max[1] = lopt.gps_loc[1];
		if (lopt.gps_loc[2] > ap_cur->gps_loc_max[2])
			ap_cur->gps_loc_max[2] = lopt.gps_loc[2];

		if (lopt.gps_loc[0] < ap_cur->gps_loc_min[0])
			ap_cur->gps_loc_min[0] = lopt.gps_loc[0];
		if (lopt.gps_loc[1] < ap_cur->gps_loc_min[1])
			ap_cur->gps_loc_min[1] = lopt.gps_loc[1];
		if (lopt.gps_loc[2] < ap_cur->gps_loc_min[2])
			ap_cur->gps_loc_min[2] = lopt.gps_loc[2];
		//        printf("seqnum: %i\n", seq);

		if (ap_cur->fcapt == 0 && ap_cur->fmiss == 0)
			gettimeofday(&(ap_cur->ftimef), NULL);
		if (ap_cur->last_seq != 0)
			ap_cur->fmiss += (seq - ap_cur->last_seq - 1);
		ap_cur->last_seq = (uint16_t) seq;
		ap_cur->fcapt++;
		gettimeofday(&(ap_cur->ftimel), NULL);

		/* if we are writing to a file and want to make a continuous rolling log save the data here */
		if (opt.record_data && opt.output_format_log_csv)
		{
			/* Write out our rolling log every time we see data from an AP */

			dump_write_airodump_ng_logcsv_add_ap(
				ap_cur, ri->ri_power, &lopt.gps_time, lopt.gps_loc);
		}

		//         if(ap_cur->fcapt >= QLT_COUNT) update_rx_quality();
	}

	switch (h80211[0])
	{
		case IEEE80211_FC0_SUBTYPE_BEACON:
			ap_cur->nb_bcn++;
			break;

		case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
			/* reset the WPS state */
			ap_cur->wps.state = 0xFF;
			ap_cur->wps.ap_setup_locked = 0;
			break;

		default:
			break;
	}

	ap_cur->nb_pkt++;

	/* locate the station MAC in the 802.11 header */

	switch (h80211[1] & IEEE80211_FC1_DIR_MASK)
	{
		case IEEE80211_FC1_DIR_NODS:

			/* if management, check that SA != BSSID */

			if (MAC_ADDRESS_EQUAL((mac_address *)(h80211 + 10), &bssid))
			{
				goto skip_station;
			}

			MAC_ADDRESS_COPY(&stmac, (mac_address *)(h80211 + 10));
			break;

		case IEEE80211_FC1_DIR_TODS:

			/* ToDS packet, must come from a client */

			MAC_ADDRESS_COPY(&stmac, (mac_address *)(h80211 + 10));
			break;

		case IEEE80211_FC1_DIR_FROMDS:

			/* FromDS packet, reject broadcast MACs */

			if ((h80211[4] % 2) != 0)
			{
				goto skip_station;
			}
			MAC_ADDRESS_COPY(&stmac, (mac_address *)(h80211 + 4));
			break;

		case IEEE80211_FC1_DIR_DSTODS:
			goto skip_station;

		default:
			abort();
	}

	/* update our chained list of wireless stations */

	st_cur = sta_info_lookup(&lopt.sta_list[lopt.current_sta_list_index], &stmac);

	/* If it's a new client, add it */
	if (st_cur == NULL)
	{
        st_cur = calloc(1, sizeof(*st_cur));
        if (st_cur == NULL)
		{
			perror("calloc failed");
			return (1);
		}

		/* if mac is listed as unknown, remove it */
		remove_namac(&stmac);

        MAC_ADDRESS_COPY(&st_cur->stmac, &stmac);

		if (st_cur->manuf == NULL)
		{
			st_cur->manuf = get_manufacturer(
				st_cur->stmac.addr[0], st_cur->stmac.addr[1], st_cur->stmac.addr[2]);
		}

		st_cur->nb_pkt = 0;

		st_cur->tinit = time(NULL);
		st_cur->tlast = time(NULL);
        st_cur->time_printed = 0;

		st_cur->power = -1;
		st_cur->best_power = -1;
		st_cur->rate_to = -1;
		st_cur->rate_from = -1;

		st_cur->probe_index = -1;
		st_cur->missed = 0;
		st_cur->lastseq = 0;
		st_cur->qos_fr_ds = 0;
		st_cur->qos_to_ds = 0;
		st_cur->channel = 0;
        st_cur->old_channel = 0; 

		gettimeofday(&(st_cur->ftimer), NULL);

		memcpy(st_cur->gps_loc_min, //-V512
			   lopt.gps_loc,
			   sizeof(st_cur->gps_loc_min));
		memcpy(st_cur->gps_loc_max, //-V512
			   lopt.gps_loc,
			   sizeof(st_cur->gps_loc_max));
		memcpy( //-V512
			st_cur->gps_loc_best,
			lopt.gps_loc,
			sizeof(st_cur->gps_loc_best));

		for (i = 0; i < NB_PRB; i++)
		{
			memset(st_cur->probes[i], 0, sizeof(st_cur->probes[i]));
			st_cur->ssid_length[i] = 0;
		}

		TAILQ_INSERT_TAIL(&lopt.sta_list[lopt.current_sta_list_index], st_cur, entry);
	}

    if (st_cur->base == NULL || !MAC_ADDRESS_IS_BROADCAST(&ap_cur->bssid))
    {
		st_cur->base = ap_cur;
    }

	// update bitrate to station
	if ((h80211[1] & 3) == 2) st_cur->rate_to = ri->ri_rate;

	/* update the last time seen */

	st_cur->tlast = time(NULL);

	/* only update power if packets comes from the
	 * client: either type == Mgmt and SA != BSSID,
	 * or FromDS == 0 and ToDS == 1 */

	if (((h80211[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_NODS
		 && !MAC_ADDRESS_EQUAL((mac_address *)(h80211 + 10), &bssid))
		|| ((h80211[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_TODS))
	{
		st_cur->power = ri->ri_power;
		if (ri->ri_power > st_cur->best_power)
		{
			st_cur->best_power = ri->ri_power;
			memcpy(ap_cur->gps_loc_best, //-V512
				   lopt.gps_loc,
				   sizeof(st_cur->gps_loc_best));
		}

		st_cur->rate_from = ri->ri_rate;
		if (ri->ri_channel > 0 && ri->ri_channel <= HIGHEST_CHANNEL)
			st_cur->channel = ri->ri_channel;
		else
			st_cur->channel = lopt.channel[cardnum];

		if (lopt.gps_loc[0] > st_cur->gps_loc_max[0])
			st_cur->gps_loc_max[0] = lopt.gps_loc[0];
		if (lopt.gps_loc[1] > st_cur->gps_loc_max[1])
			st_cur->gps_loc_max[1] = lopt.gps_loc[1];
		if (lopt.gps_loc[2] > st_cur->gps_loc_max[2])
			st_cur->gps_loc_max[2] = lopt.gps_loc[2];

		if (lopt.gps_loc[0] < st_cur->gps_loc_min[0])
			st_cur->gps_loc_min[0] = lopt.gps_loc[0];
		if (lopt.gps_loc[1] < st_cur->gps_loc_min[1])
			st_cur->gps_loc_min[1] = lopt.gps_loc[1];
		if (lopt.gps_loc[2] < st_cur->gps_loc_min[2])
			st_cur->gps_loc_min[2] = lopt.gps_loc[2];

		if (st_cur->lastseq != 0)
		{
			msd = seq - st_cur->lastseq - 1;
			if (msd > 0 && msd < 1000) st_cur->missed += msd;
		}
		st_cur->lastseq = (uint16_t) seq;

		/* if we are writing to a file and want to make a continuous rolling log save the data here */
		if (opt.record_data && opt.output_format_log_csv)
		{
			/* Write out our rolling log every time we see data from a client */
			dump_write_airodump_ng_logcsv_add_client(
				ap_cur, st_cur, ri->ri_power, &lopt.gps_time, lopt.gps_loc);
		}
	}

	st_cur->nb_pkt++;

skip_station:

	/* packet parsing: Probe Request */

	if (h80211[0] == IEEE80211_FC0_SUBTYPE_PROBE_REQ && st_cur != NULL)
	{
		p = h80211 + 24;

		while (p < h80211 + caplen)
		{
			if (p + 2 + p[1] > h80211 + caplen) break;

			if (p[0] == 0x00 && p[1] > 0 && p[2] != '\0'
				&& (p[1] > 1 || p[2] != ' '))
			{
				n = MIN(ESSID_LENGTH, p[1]);

                for (i = 0; i < n; i++)
                {
					if (p[2 + i] > 0 && p[2 + i] < ' ') goto skip_probe;
                }

				/* got a valid ASCII probed ESSID, check if it's
				   already in the ring buffer */

                for (i = 0; i < NB_PRB; i++)
                {
                    if (memcmp(st_cur->probes[i], p + 2, n) == 0)
                    {
                        goto skip_probe;
                    }
                }

				st_cur->probe_index = (st_cur->probe_index + 1) % NB_PRB;
                memset(st_cur->probes[st_cur->probe_index], 0, sizeof st_cur->probes[st_cur->probe_index]);
				memcpy(
					st_cur->probes[st_cur->probe_index], p + 2, n); // twice?!
				st_cur->ssid_length[st_cur->probe_index] = (int) n;

				if (verifyssid((const unsigned char *)
								   st_cur->probes[st_cur->probe_index])
					== 0)
					for (i = 0; i < n; i++)
					{
						c = p[2 + i];
						if (c < 32) c = '.';
						st_cur->probes[st_cur->probe_index][i] = c;
					}
			}

			p += 2 + p[1];
		}
	}

skip_probe:

	/* packet parsing: Beacon or Probe Response */

	if (h80211[0] == IEEE80211_FC0_SUBTYPE_BEACON
		|| h80211[0] == IEEE80211_FC0_SUBTYPE_PROBE_RESP)
	{
		if (!(ap_cur->security & (STD_OPN | STD_WEP | STD_WPA | STD_WPA2)))
		{
			if ((h80211[34] & 0x10) >> 4)
				ap_cur->security |= STD_WEP | ENC_WEP;
			else
				ap_cur->security |= STD_OPN;
		}

		ap_cur->preamble = (h80211[34] & 0x20) >> 5;

		unsigned long long * tstamp = (unsigned long long *) (h80211 + 24);
		ap_cur->timestamp = letoh64(*tstamp);

		p = h80211 + 36;

		while (p < h80211 + caplen)
		{
			if (p + 2 + p[1] > h80211 + caplen) break;

			// only update the essid length if the new length is > the old one
			if (p[0] == 0x00 && (ap_cur->ssid_length < p[1]))
				ap_cur->ssid_length = p[1];

			if (p[0] == 0x00 && p[1] > 0 && p[2] != '\0'
				&& (p[1] > 1 || p[2] != ' '))
			{
				/* found a non-cloaked ESSID */
				n = MIN(ESSID_LENGTH, p[1]);

                memset(ap_cur->essid, 0, sizeof ap_cur->essid);
				memcpy(ap_cur->essid, p + 2, n);

				if (opt.f_ivs != NULL && !ap_cur->essid_stored)
				{
                    memset(&ivs2, '\x00', sizeof ivs2);
					ivs2.flags |= IVS2_ESSID;
					ivs2.len += ap_cur->ssid_length;

                    if (!MAC_ADDRESS_EQUAL(&lopt.prev_bssid, &ap_cur->bssid))
					{
						ivs2.flags |= IVS2_BSSID;
                        ivs2.len += MAC_ADDRESS_LEN;
                        MAC_ADDRESS_COPY(&lopt.prev_bssid, &ap_cur->bssid);
					}

					/* write header */
                    if (fwrite(&ivs2, 1, sizeof ivs2, opt.f_ivs) != sizeof ivs2)
					{
						perror("fwrite(IV header) failed");
						return (1);
					}

					/* write BSSID */
					if (ivs2.flags & IVS2_BSSID)
					{
                        if (fwrite(&ap_cur->bssid, 1, sizeof ap_cur->bssid, opt.f_ivs)
                            != sizeof ap_cur->bssid)
						{
							perror("fwrite(IV bssid) failed");
							return (1);
						}
					}

					/* write essid */
					if (fwrite(ap_cur->essid,
							   1,
							   (size_t) ap_cur->ssid_length,
							   opt.f_ivs)
						!= (size_t) ap_cur->ssid_length)
					{
						perror("fwrite(IV essid) failed");
						return (1);
					}

					ap_cur->essid_stored = 1;
				}

				if (verifyssid(ap_cur->essid) == 0)
					for (i = 0; i < n; i++)
						if (ap_cur->essid[i] < 32) ap_cur->essid[i] = '.';
			}

			/* get the maximum speed in Mb and the AP's channel */

			if (p[0] == 0x01 || p[0] == 0x32)
			{
				if (ap_cur->max_speed < (p[1 + p[1]] & 0x7F) / 2)
					ap_cur->max_speed = (p[1 + p[1]] & 0x7F) / 2;
			}

			if (p[0] == 0x03)
			{
				ap_cur->channel = p[2];
			}
			else if (p[0] == 0x3d)
			{
				if (ap_cur->standard[0] == '\0')
				{
					ap_cur->standard[0] = 'n';
				}

				/* also get the channel from ht information->primary channel */
				ap_cur->channel = p[2];

				// Get channel width and secondary channel
				switch (p[3] % 4)
				{
					case 0:
						// 20MHz
						ap_cur->channel_width = CHANNEL_20MHZ;
						break;
					case 1:
						// Above
						ap_cur->n_channel.sec_channel = 1;
						switch (ap_cur->channel_width)
						{
							case CHANNEL_UNKNOWN_WIDTH:
							case CHANNEL_3MHZ:
							case CHANNEL_5MHZ:
							case CHANNEL_10MHZ:
							case CHANNEL_20MHZ:
							case CHANNEL_22MHZ:
							case CHANNEL_30MHZ:
							case CHANNEL_20_OR_40MHZ:
								ap_cur->channel_width = CHANNEL_40MHZ;
								break;
							default:
								break;
						}
						break;
					case 2:
						// Reserved
						break;
					case 3:
						// Below
						ap_cur->n_channel.sec_channel = -1;
						switch (ap_cur->channel_width)
						{
							case CHANNEL_UNKNOWN_WIDTH:
							case CHANNEL_3MHZ:
							case CHANNEL_5MHZ:
							case CHANNEL_10MHZ:
							case CHANNEL_20MHZ:
							case CHANNEL_22MHZ:
							case CHANNEL_30MHZ:
							case CHANNEL_20_OR_40MHZ:
								ap_cur->channel_width = CHANNEL_40MHZ;
								break;
							default:
								break;
						}
						break;
					default:
						break;
				}

				ap_cur->n_channel.any_chan_width = (uint8_t)((p[3] / 4) % 2);
			}

			// HT capabilities
			if (p[0] == 0x2d && p[1] > 18)
			{
				if (ap_cur->standard[0] == '\0')
				{
					ap_cur->standard[0] = 'n';
				}

				// Short GI for 20/40MHz
				ap_cur->n_channel.short_gi_20 = (uint8_t)((p[3] / 32) % 2);
				ap_cur->n_channel.short_gi_40 = (uint8_t)((p[3] / 64) % 2);

				// Parse MCS rate
				/*
				 * XXX: Sometimes TX and RX spatial stream # differ and none of
				 * the beacon
				 * have that. If someone happens to have such AP, open an issue
				 * with it.
				 * Ref:
				 * https://www.wireshark.org/lists/wireshark-bugs/201307/msg00098.html
				 * See IEEE standard 802.11-2012 table 8.126
				 *
				 * For now, just figure out the highest MCS rate.
				 */
				if (ap_cur->n_channel.mcs_index == -1)
				{
					uint32_t rx_mcs_bitmask = 0;
					memcpy(&rx_mcs_bitmask, p + 5, sizeof(uint32_t));
					while (rx_mcs_bitmask)
					{
						++(ap_cur->n_channel.mcs_index);
						rx_mcs_bitmask /= 2;
					}
				}
			}

			// VHT Capabilities
			if (p[0] == 0xbf && p[1] >= 12)
			{
				// Standard is AC
				strcpy(ap_cur->standard, "ac");

				ap_cur->ac_channel.split_chan = (uint8_t)((p[3] / 4) % 4);

				ap_cur->ac_channel.short_gi_80 = (uint8_t)((p[3] / 32) % 2);
				ap_cur->ac_channel.short_gi_160 = (uint8_t)((p[3] / 64) % 2);

				ap_cur->ac_channel.mu_mimo = (uint8_t)((p[4] & 0b11000) % 2);

				// A few things indicate Wave 2: MU-MIMO, 80+80 Channels
				ap_cur->ac_channel.wave_2
					= (uint8_t)((ap_cur->ac_channel.mu_mimo
								 || ap_cur->ac_channel.split_chan)
								% 2);

				// Maximum rates (16 bit)
				uint16_t tx_mcs = 0;
				memcpy(&tx_mcs, p + 10, sizeof(uint16_t));

				// Maximum of 8 SS, each uses 2 bits
				for (uint8_t stream_idx = 0; stream_idx < MAX_AC_MCS_INDEX;
					 ++stream_idx)
				{
					uint8_t mcs = (uint8_t)(tx_mcs % 4);

					// Unsupported -> No more spatial stream
					if (mcs == 3)
					{
						break;
					}
					switch (mcs)
					{
						case 0:
							// support of MCS 0-7
							ap_cur->ac_channel.mcs_index[stream_idx] = 7;
							break;
						case 1:
							// support of MCS 0-8
							ap_cur->ac_channel.mcs_index[stream_idx] = 8;
							break;
						case 2:
							// support of MCS 0-9
							ap_cur->ac_channel.mcs_index[stream_idx] = 9;
							break;
						default:
							break;
					}

					// Next spatial stream
					tx_mcs /= 4;
				}
			}

			// VHT Operations
			if (p[0] == 0xc0 && p[1] >= 3)
			{
				// Standard is AC
				strcpy(ap_cur->standard, "ac");

				// Channel width
				switch (p[2])
				{
					case 0:
						// 20 or 40MHz
						ap_cur->channel_width = CHANNEL_20_OR_40MHZ;
						break;
					case 1:
						ap_cur->channel_width = CHANNEL_80MHZ;
						break;
					case 2:
						ap_cur->channel_width = CHANNEL_160MHZ;
						break;
					case 3:
						// 80+80MHz
						ap_cur->channel_width = CHANNEL_80_80MHZ;
						ap_cur->ac_channel.split_chan = 1;
						break;
					default:
						break;
				}

				// 802.11ac channel center segments
				ap_cur->ac_channel.center_sgmt[0] = p[3];
				ap_cur->ac_channel.center_sgmt[1] = p[4];
			}

			// Next
			p += 2 + p[1];
		}

		// Now get max rate
		if (ap_cur->standard[0] == 'n' || strcmp(ap_cur->standard, "ac") == 0)
		{
			int sgi = 0;
			int width = 0;

			switch (ap_cur->channel_width)
			{
				case CHANNEL_20MHZ:
					width = 20;
					sgi = ap_cur->n_channel.short_gi_20;
					break;
				case CHANNEL_20_OR_40MHZ:
				case CHANNEL_40MHZ:
					width = 40;
					sgi = ap_cur->n_channel.short_gi_40;
					break;
				case CHANNEL_80MHZ:
					width = 80;
					sgi = ap_cur->ac_channel.short_gi_80;
					break;
				case CHANNEL_80_80MHZ:
				case CHANNEL_160MHZ:
					width = 160;
					sgi = ap_cur->ac_channel.short_gi_160;
					break;
				default:
					break;
			}

			if (width != 0)
			{
				// In case of ac, get the amount of spatial streams
				int amount_ss = 1;
				if (ap_cur->standard[0] != 'n')
				{
					for (amount_ss = 0;
						 amount_ss < MAX_AC_MCS_INDEX
						 && ap_cur->ac_channel.mcs_index[amount_ss] != 0;
						 ++amount_ss)
						;
				}

				// Get rate
				float max_rate
					= (ap_cur->standard[0] == 'n')
						  ? get_80211n_rate(
								width, sgi, ap_cur->n_channel.mcs_index)
						  : get_80211ac_rate(
								width,
								sgi,
								ap_cur->ac_channel.mcs_index[amount_ss - 1],
								amount_ss);

				// If no error, update rate
				if (max_rate > 0)
				{
					ap_cur->max_speed = (int) max_rate;
				}
			}
		}
	}

	/* packet parsing: Beacon & Probe response */
	/* TODO: Merge this if and the one above */
	if ((h80211[0] == IEEE80211_FC0_SUBTYPE_BEACON
		 || h80211[0] == IEEE80211_FC0_SUBTYPE_PROBE_RESP)
		&& caplen > 38)
	{
		p = h80211 + 36; // ignore hdr + fixed params

		while (p < h80211 + caplen)
		{
			type = p[0];
			length = p[1];
			if (p + 2 + length > h80211 + caplen)
			{
				/*                printf("error parsing tags! %p vs. %p (tag:
				%i, length: %i,position: %i)\n", (p+2+length), (h80211+caplen),
				type, length, (p-h80211));
				exit(1);*/
				break;
			}

			// Find WPA and RSN tags
			if ((type == 0xDD && (length >= 8)
				 && (memcmp(p + 2, "\x00\x50\xF2\x01\x01\x00", 6) == 0))
				|| (type == 0x30))
			{
				ap_cur->security &= ~(STD_WEP | ENC_WEP | STD_WPA);

				org_p = p;
				offset = 0;

				if (type == 0xDD)
				{
					// WPA defined in vendor specific tag -> WPA1 support
					ap_cur->security |= STD_WPA;
					offset = 4;
				}

				// RSN => WPA2
				if (type == 0x30)
				{
					offset = 0;
				}

				if (length < (18 + offset))
				{
					p += length + 2;
					continue;
				}

				// Number of pairwise cipher suites
				if (p + 9 + offset > h80211 + caplen) break;
				numuni = p[8 + offset] + (p[9 + offset] << 8);

				// Number of Authentication Key Managament suites
				if (p + (11 + offset) + 4 * numuni > h80211 + caplen) break;
				numauth = p[(10 + offset) + 4 * numuni]
						  + (p[(11 + offset) + 4 * numuni] << 8);

				p += (10 + offset);

				if (type != 0x30)
				{
					if (p + (4 * numuni) + (2 + 4 * numauth) > h80211 + caplen)
						break;
				}
				else
				{
					if (p + (4 * numuni) + (2 + 4 * numauth) + 2
						> h80211 + caplen)
						break;
				}

				// Get the list of cipher suites
				for (i = 0; i < (size_t) numuni; i++)
				{
					switch (p[i * 4 + 3])
					{
						case 0x01:
							ap_cur->security |= ENC_WEP;
							break;
						case 0x02:
							ap_cur->security |= ENC_TKIP;
							ap_cur->security &= ~STD_WPA2;
							break;
						case 0x03:
							ap_cur->security |= ENC_WRAP;
							break;
						case 0x0A:
						case 0x04:
							ap_cur->security |= ENC_CCMP;
							ap_cur->security |= STD_WPA2;
							break;
						case 0x05:
							ap_cur->security |= ENC_WEP104;
							break;
						case 0x08:
						case 0x09:
							ap_cur->security |= ENC_GCMP;
							ap_cur->security |= STD_WPA2;
							break;
						case 0x0B:
						case 0x0C:
							ap_cur->security |= ENC_GMAC;
							ap_cur->security |= STD_WPA2;
							break;
						default:
							break;
					}
				}

				p += 2 + 4 * numuni;

				// Get the AKM suites
				for (i = 0; i < numauth; i++)
				{
					switch (p[i * 4 + 3])
					{
						case 0x01:
							ap_cur->security |= AUTH_MGT;
							break;
						case 0x02:
							ap_cur->security |= AUTH_PSK;
							break;
						case 0x06:
						case 0x0d:
							ap_cur->security |= AUTH_CMAC;
							break;
						case 0x08:
							ap_cur->security |= AUTH_SAE;
							break;
						case 0x12:
							ap_cur->security |= AUTH_OWE;
							break;
						default:
							break;
					}
				}

				p = org_p + length + 2;
			}
			else if ((type == 0xDD && (length >= 8)
					  && (memcmp(p + 2, "\x00\x50\xF2\x02\x01\x01", 6) == 0)))
			{
				// QoS IE
				ap_cur->security |= STD_QOS;
				p += length + 2;
			}
			else if ((type == 0xDD && (length >= 4)
					  && (memcmp(p + 2, "\x00\x50\xF2\x04", 4) == 0)))
			{
				// WPS IE
				org_p = p;
				p += 6;
				int len = length, subtype = 0, sublen = 0;
				while (len >= 4)
				{
					subtype = (p[0] << 8) + p[1];
					sublen = (p[2] << 8) + p[3];
					if (sublen > len) break;
					switch (subtype)
					{
						case 0x104a: // WPS Version
							ap_cur->wps.version = p[4];
							break;
						case 0x1011: // Device Name
						case 0x1012: // Device Password ID
						case 0x1021: // Manufacturer
						case 0x1023: // Model
						case 0x1024: // Model Number
						case 0x103b: // Response Type
						case 0x103c: // RF Bands
						case 0x1041: // Selected Registrar
						case 0x1042: // Serial Number
							break;
						case 0x1044: // WPS State
							ap_cur->wps.state = p[4];
							break;
						case 0x1047: // UUID Enrollee
						case 0x1049: // Vendor Extension
							if (memcmp(&p[4], "\x00\x37\x2A", 3) == 0)
							{
								unsigned char * pwfa = &p[7];
								int wfa_len = ntohs(*((short *) &p[2]));
								while (wfa_len > 0)
								{
									if (*pwfa == 0)
									{ // Version2
										ap_cur->wps.version = pwfa[2];
										break;
									}
									wfa_len -= pwfa[1] + 2;
									pwfa += pwfa[1] + 2;
								}
							}
							break;
						case 0x1054: // Primary Device Type
							break;
						case 0x1057: // AP Setup Locked
							ap_cur->wps.ap_setup_locked = p[4];
							break;
						case 0x1008: // Config Methods
						case 0x1053: // Selected Registrar Config Methods
							ap_cur->wps.meth = (p[4] << 8) + p[5];
							break;
						default: // Unknown type-length-value
							break;
					}
					p += sublen + 4;
					len -= sublen + 4;
				}
				p = org_p + length + 2;
			}
			else
				p += length + 2;
		}
	}

	/* packet parsing: Authentication Response */

	if (h80211[0] == IEEE80211_FC0_SUBTYPE_AUTH && caplen >= 30)
	{
		if (ap_cur->security & STD_WEP)
		{
			// successful step 2 or 4 (coming from the AP)
			if (memcmp(h80211 + 28, "\x00\x00", 2) == 0
				&& (h80211[26] == 0x02 || h80211[26] == 0x04))
			{
				ap_cur->security &= ~(AUTH_OPN | AUTH_PSK | AUTH_MGT);
				if (h80211[24] == 0x00) ap_cur->security |= AUTH_OPN;
				if (h80211[24] == 0x01) ap_cur->security |= AUTH_PSK;
			}
		}
	}

	/* packet parsing: Association Request */

	if (h80211[0] == IEEE80211_FC0_SUBTYPE_ASSOC_REQ && caplen > 28)
	{
		p = h80211 + 28;

		while (p < h80211 + caplen)
		{
			if (p + 2 + p[1] > h80211 + caplen) break;

			if (p[0] == 0x00 && p[1] > 0 && p[2] != '\0'
				&& (p[1] > 1 || p[2] != ' '))
			{
				/* found a non-cloaked ESSID */
				n = MIN(ESSID_LENGTH, p[1]);

				memset(ap_cur->essid, 0, ESSID_LENGTH + 1);
				memcpy(ap_cur->essid, p + 2, n);
				ap_cur->ssid_length = (int) n;

				if (opt.f_ivs != NULL && !ap_cur->essid_stored)
				{
                    memset(&ivs2, '\x00', sizeof ivs2);
					ivs2.flags |= IVS2_ESSID;
					ivs2.len += ap_cur->ssid_length;

                    if (!MAC_ADDRESS_EQUAL(&lopt.prev_bssid, &ap_cur->bssid))
					{
						ivs2.flags |= IVS2_BSSID;
                        ivs2.len += MAC_ADDRESS_LEN;
                        MAC_ADDRESS_COPY(&lopt.prev_bssid, &ap_cur->bssid);
					}

					/* write header */
                    if (fwrite(&ivs2, 1, sizeof ivs2, opt.f_ivs) != sizeof ivs2)
					{
						perror("fwrite(IV header) failed");
						return (1);
					}

					/* write BSSID */
					if (ivs2.flags & IVS2_BSSID)
					{
                        if (fwrite(&ap_cur->bssid, 1, sizeof ap_cur->bssid, opt.f_ivs)
                            != sizeof ap_cur->bssid)
						{
							perror("fwrite(IV bssid) failed");
							return (1);
						}
					}

					/* write essid */
					if (fwrite(ap_cur->essid,
							   1,
							   (size_t) ap_cur->ssid_length,
							   opt.f_ivs)
						!= (size_t) ap_cur->ssid_length)
					{
						perror("fwrite(IV essid) failed");
						return (1);
					}

					ap_cur->essid_stored = 1;
				}

				if (verifyssid(ap_cur->essid) == 0)
					for (i = 0; i < n; i++)
						if (ap_cur->essid[i] < 32) ap_cur->essid[i] = '.';
			}

			p += 2 + p[1];
		}
		if (st_cur != NULL) st_cur->wpa.state = 0;
	}

	/* packet parsing: some data */

	if ((h80211[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_DATA)
	{
		/* update the channel if we didn't get any beacon */

		if (ap_cur->channel == -1)
		{
			if (ri->ri_channel > 0 && ri->ri_channel <= HIGHEST_CHANNEL)
				ap_cur->channel = ri->ri_channel;
			else
				ap_cur->channel = lopt.channel[cardnum];
		}

		/* check the SNAP header to see if data is encrypted */

		z = ((h80211[1] & IEEE80211_FC1_DIR_MASK) != IEEE80211_FC1_DIR_DSTODS)
				? 24
				: 30;

		/* Check if 802.11e (QoS) */
		if ((h80211[0] & 0x80) == 0x80)
		{
			z += 2;
			if (st_cur != NULL)
			{
				if ((h80211[1] & 3) == 1) // ToDS
					st_cur->qos_to_ds = 1;
				else
					st_cur->qos_fr_ds = 1;
			}
		}
		else
		{
			if (st_cur != NULL)
			{
				if ((h80211[1] & 3) == 1) // ToDS
					st_cur->qos_to_ds = 0;
				else
					st_cur->qos_fr_ds = 0;
			}
		}

		if (z == 24)
		{
			if (ap_cur->decloak_detect)
			{
				if (list_check_decloak(&ap_cur->pkt_list, caplen, h80211) != 0)
				{
					list_add_packet(&ap_cur->pkt_list, caplen, h80211);
				}
				else
				{
					ap_cur->is_decloak = 1;
					ap_cur->decloak_detect = 0;

					packet_list_free(&ap_cur->pkt_list);

					snprintf(lopt.message,
							 sizeof(lopt.message),
							 "][ Decloak: %02X:%02X:%02X:%02X:%02X:%02X ",
							 ap_cur->bssid.addr[0],
							 ap_cur->bssid.addr[1],
							 ap_cur->bssid.addr[2],
							 ap_cur->bssid.addr[3],
							 ap_cur->bssid.addr[4],
							 ap_cur->bssid.addr[5]);
				}
			}
		}

		if (z + 26 > (unsigned)caplen)
		{
			goto write_packet;
		}

		if (h80211[z] == h80211[z + 1] && h80211[z + 2] == 0x03)
		{
			//            if( ap_cur->encryption < 0 )
			//                ap_cur->encryption = 0;

			/* if ethertype == IPv4, find the LAN address */

			if (h80211[z + 6] == 0x08 && h80211[z + 7] == 0x00
				&& (h80211[1] & 3) == 0x01)
				memcpy(ap_cur->lanip, &h80211[z + 20], 4);

			if (h80211[z + 6] == 0x08 && h80211[z + 7] == 0x06)
				memcpy(ap_cur->lanip, &h80211[z + 22], 4);
		}
		//        else
		//            ap_cur->encryption = 2 + ( ( h80211[z + 3] & 0x20 ) >> 5
		//            );

		if (ap_cur->security == 0 || (ap_cur->security & STD_WEP))
		{
			if ((h80211[1] & 0x40) != 0x40)
			{
				ap_cur->security |= STD_OPN;
			}
			else
			{
				if ((h80211[z + 3] & 0x20) == 0x20)
				{
					ap_cur->security |= STD_WPA;
				}
				else
				{
					ap_cur->security |= STD_WEP;
					if ((h80211[z + 3] & 0xC0) != 0x00)
					{
						ap_cur->security |= ENC_WEP40;
					}
					else
					{
						ap_cur->security &= ~ENC_WEP40;
						ap_cur->security |= ENC_WEP;
					}
				}
			}
		}

		if (z + 10 > (unsigned)caplen)
		{
			goto write_packet;
		}

		if (ap_cur->security & STD_WEP)
		{
			/* WEP: check if we've already seen this IV */

			if (!uniqueiv_check(ap_cur->uiv_root, &h80211[z]))
			{
				/* first time seen IVs */

				if (opt.f_ivs != NULL)
				{
                    memset(&ivs2, '\x00', sizeof ivs2);
					ivs2.flags = 0;
					ivs2.len = 0;

					/* datalen = caplen - (header+iv+ivs) */
					dlen = caplen - z - 4 - 4; // original data len
					if (dlen > 2048)
					{
						dlen = 2048;
					}
					// get cleartext + len + 4(iv+idx)
					num_xor = known_clear(clear, &clen, weight, h80211, dlen);
					if (num_xor == 1)
					{
						ivs2.flags |= IVS2_XOR;
						ivs2.len += clen + 4;
						/* reveal keystream (plain^encrypted) */
						for (n = 0; n < (size_t)(ivs2.len - 4); n++)
						{
							clear[n] = (uint8_t)((clear[n] ^ h80211[z + 4 + n])
												 & 0xFF);
						}
						// clear is now the keystream
					}
					else
					{
						// do it again to get it 2 bytes higher
						num_xor = known_clear(
							clear + 2, &clen, weight, h80211, dlen);
						ivs2.flags |= IVS2_PTW;
						// len = 4(iv+idx) + 1(num of keystreams) + 1(len per
						// keystream) + 32*num_xor + 16*sizeof(int)(weight[16])
						ivs2.len += 4 + 1 + 1 + 32 * num_xor + 16 * sizeof(int);
						clear[0] = (uint8_t) num_xor;
						clear[1] = (uint8_t) clen;
						/* reveal keystream (plain^encrypted) */
						for (o = 0; o < num_xor; o++)
						{
							for (n = 0; n < (size_t)(ivs2.len - 4); n++)
							{
								clear[2 + n + o * 32] = (uint8_t)(
									(clear[2 + n + o * 32] ^ h80211[z + 4 + n])
									& 0xFF);
							}
						}
						memcpy(clear + 4 + 1 + 1 + 32 * num_xor,
							   weight,
							   16 * sizeof(int));
						// clear is now the keystream
					}

                    if (!MAC_ADDRESS_EQUAL(&lopt.prev_bssid, &ap_cur->bssid))
					{
						ivs2.flags |= IVS2_BSSID;
                        ivs2.len += MAC_ADDRESS_LEN;
                        MAC_ADDRESS_COPY(&lopt.prev_bssid, &ap_cur->bssid);
					}

                    if (fwrite(&ivs2, 1, sizeof ivs2, opt.f_ivs) != sizeof ivs2)
					{
						perror("fwrite(IV header) failed");
						return (EXIT_FAILURE);
					}

					if (ivs2.flags & IVS2_BSSID)
					{
                        if (fwrite(&ap_cur->bssid, 1, sizeof ap_cur->bssid, opt.f_ivs)
                            != sizeof ap_cur->bssid)
						{
							perror("fwrite(IV bssid) failed");
							return (1);
						}
                        ivs2.len -= sizeof ap_cur->bssid;
					}

					if (fwrite(h80211 + z, 1, 4, opt.f_ivs) != (size_t) 4)
					{
						perror("fwrite(IV iv+idx) failed");
						return (EXIT_FAILURE);
					}
					ivs2.len -= 4;

					if (fwrite(clear, 1, ivs2.len, opt.f_ivs)
						!= (size_t) ivs2.len)
					{
						perror("fwrite(IV keystream) failed");
						return (EXIT_FAILURE);
					}
				}

				uniqueiv_mark(ap_cur->uiv_root, &h80211[z]);

				ap_cur->nb_data++;
			}

			// Record all data linked to IV to detect WEP Cloaking
			if (opt.f_ivs == NULL && lopt.detect_anomaly)
			{
				// Only allocate this when seeing WEP AP
				if (ap_cur->data_root == NULL)
				{
					ap_cur->data_root = data_init();
				}

				// Only works with full capture, not IV-only captures
				if (data_check(ap_cur->data_root, &h80211[z], &h80211[z + 4])
						== CLOAKING
					&& ap_cur->EAP_detected == 0)
				{

					// If no EAP/EAP was detected, indicate WEP cloaking
					snprintf(lopt.message,
							 sizeof(lopt.message),
							 "][ WEP Cloaking: %02X:%02X:%02X:%02X:%02X:%02X ",
                             ap_cur->bssid.addr[0],
                             ap_cur->bssid.addr[1],
                             ap_cur->bssid.addr[2],
                             ap_cur->bssid.addr[3],
                             ap_cur->bssid.addr[4],
                             ap_cur->bssid.addr[5]);
				}
			}
		}
		else
		{
			ap_cur->nb_data++;
		}

		z = ((h80211[1] & IEEE80211_FC1_DIR_MASK) != IEEE80211_FC1_DIR_DSTODS)
				? 24
				: 30;

		/* Check if 802.11e (QoS) */
		if ((h80211[0] & 0x80) == 0x80) z += 2;

		if (z + 26 > (unsigned)caplen)
		{
			goto write_packet;
		}

		z += 6; // skip LLC header

		/* check ethertype == EAPOL */
		if (h80211[z] == 0x88 && h80211[z + 1] == 0x8E
			&& (h80211[1] & 0x40) != 0x40)
		{
			ap_cur->EAP_detected = 1;

			z += 2; // skip ethertype

			if (st_cur == NULL) goto write_packet;

			/* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */

			if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) == 0
				&& (h80211[z + 6] & 0x80) != 0
				&& (h80211[z + 5] & 0x01) == 0)
			{
				memcpy(st_cur->wpa.anonce, &h80211[z + 17], 32);

				st_cur->wpa.state = 1;

				if (h80211[z + 99] == 0xdd) // RSN
				{
					if (h80211[z + 101] == 0x00 && h80211[z + 102] == 0x0f
						&& h80211[z + 103] == 0xac) // OUI: IEEE8021
					{
						if (h80211[z + 104] == 0x04) // OUI SUBTYPE
						{
							// Got a PMKID value?!
							memcpy(st_cur->wpa.pmkid, &h80211[z + 105], 16);

							/* copy the key descriptor version */
							st_cur->wpa.keyver = (uint8_t)(h80211[z + 6] & 7);

							MAC_ADDRESS_COPY(&st_cur->wpa.stmac, &st_cur->stmac);
							MAC_ADDRESS_COPY(&lopt.wpa_bssid, &ap_cur->bssid);
							snprintf(lopt.message,
									 sizeof(lopt.message),
									 "][ PMKID found: "
									 "%02X:%02X:%02X:%02X:%02X:%02X ",
									 lopt.wpa_bssid.addr[0],
									 lopt.wpa_bssid.addr[1],
									 lopt.wpa_bssid.addr[2],
									 lopt.wpa_bssid.addr[3],
									 lopt.wpa_bssid.addr[4],
									 lopt.wpa_bssid.addr[5]);

							goto write_packet;
						}
					}
				}
			}

			/* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */

			if (z + 17 + 32 > (unsigned)caplen)
			{
				goto write_packet;
			}

			if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) == 0
				&& (h80211[z + 6] & 0x80) == 0
				&& (h80211[z + 5] & 0x01) != 0)
			{
				if (memcmp(&h80211[z + 17], ZERO, 32) != 0)
				{
					memcpy(st_cur->wpa.snonce, &h80211[z + 17], 32);
					st_cur->wpa.state |= 2;
				}

				if ((st_cur->wpa.state & 4) != 4)
				{
					st_cur->wpa.eapol_size
						= (uint32_t)((h80211[z + 2] << 8) + h80211[z + 3] + 4);

					if (caplen - z < st_cur->wpa.eapol_size
						|| st_cur->wpa.eapol_size == 0 //-V560
						|| caplen - z < 81 + 16
						|| st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol))
					{
						// Ignore the packet trying to crash us.
						st_cur->wpa.eapol_size = 0;
						goto write_packet;
					}

					memcpy(st_cur->wpa.keymic, &h80211[z + 81], 16);
					memcpy(
						st_cur->wpa.eapol, &h80211[z], st_cur->wpa.eapol_size);
					memset(st_cur->wpa.eapol + 81, 0, 16);
					st_cur->wpa.state |= 4;
					st_cur->wpa.keyver = (uint8_t)(h80211[z + 6] & 7);
				}
			}

			/* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */

			if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) != 0
				&& (h80211[z + 6] & 0x80) != 0
				&& (h80211[z + 5] & 0x01) != 0)
			{
				if (memcmp(&h80211[z + 17], ZERO, 32) != 0)
				{
					memcpy(st_cur->wpa.anonce, &h80211[z + 17], 32);
					st_cur->wpa.state |= 1;
				}

				if ((st_cur->wpa.state & 4) != 4)
				{
					st_cur->wpa.eapol_size
						= (h80211[z + 2] << 8) + h80211[z + 3] + 4u;

					if (st_cur->wpa.eapol_size == 0 //-V560
						|| st_cur->wpa.eapol_size
							   >= sizeof(st_cur->wpa.eapol) - 16)
					{
						// Ignore the packet trying to crash us.
						st_cur->wpa.eapol_size = 0;
						goto write_packet;
					}

					memcpy(st_cur->wpa.keymic, &h80211[z + 81], 16);
					memcpy(
						st_cur->wpa.eapol, &h80211[z], st_cur->wpa.eapol_size);
					memset(st_cur->wpa.eapol + 81, 0, 16);
					st_cur->wpa.state |= 4;
					st_cur->wpa.keyver = (uint8_t)(h80211[z + 6] & 7);
				}
			}

			if (st_cur->wpa.state == 7 && !is_filtered_essid(ap_cur->essid))
			{
				MAC_ADDRESS_COPY(&st_cur->wpa.stmac, &st_cur->stmac);
				MAC_ADDRESS_COPY(&lopt.wpa_bssid, &ap_cur->bssid);
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ WPA handshake: %02X:%02X:%02X:%02X:%02X:%02X ",
						 lopt.wpa_bssid.addr[0],
						 lopt.wpa_bssid.addr[1],
						 lopt.wpa_bssid.addr[2],
						 lopt.wpa_bssid.addr[3],
						 lopt.wpa_bssid.addr[4],
						 lopt.wpa_bssid.addr[5]);

				if (opt.f_ivs != NULL)
				{
                    memset(&ivs2, '\x00', sizeof ivs2);
					ivs2.flags = 0;

					ivs2.len = sizeof(struct WPA_hdsk);
					ivs2.flags |= IVS2_WPA;

                    if (!MAC_ADDRESS_EQUAL(&lopt.prev_bssid, &ap_cur->bssid))
					{
						ivs2.flags |= IVS2_BSSID;
                        ivs2.len += MAC_ADDRESS_LEN;
                        MAC_ADDRESS_COPY(&lopt.prev_bssid, &ap_cur->bssid);
					}

                    if (fwrite(&ivs2, 1, sizeof ivs2, opt.f_ivs) != sizeof ivs2)
					{
						perror("fwrite(IV header) failed");
						return (EXIT_FAILURE);
					}

					if (ivs2.flags & IVS2_BSSID)
					{
                        if (fwrite(&ap_cur->bssid, 1, sizeof ap_cur->bssid, opt.f_ivs)
                            != sizeof ap_cur->bssid)
						{
							perror("fwrite(IV bssid) failed");
							return (EXIT_FAILURE);
						}
                        ivs2.len -= MAC_ADDRESS_LEN;
					}

					if (fwrite(&st_cur->wpa,
							   1,
                               sizeof st_cur->wpa,
							   opt.f_ivs)
                        != sizeof st_cur->wpa)
					{
						perror("fwrite(IV wpa_hdsk) failed");
						return (EXIT_FAILURE);
					}
				}
			}
		}
	}

write_packet:

	if (ap_cur != NULL)
	{
		if (h80211[0] == 0x80 && lopt.one_beacon)
		{
			if (!ap_cur->beacon_logged)
				ap_cur->beacon_logged = 1;
			else
				return (0);
		}
	}

	if (opt.record_data)
	{
		if (((h80211[0] & 0x0C) == 0x00) && ((h80211[0] & 0xF0) == 0xB0))
		{
			/* authentication packet */
			check_shared_key(h80211, (size_t) caplen);
		}
	}

	if (ap_cur != NULL)
	{
		if (ap_cur->security != 0 && lopt.f_encrypt != 0
			&& ((ap_cur->security & lopt.f_encrypt) == 0))
		{
			return (1);
		}

		if (is_filtered_essid(ap_cur->essid))
		{
			return (1);
		}
	}

	/* this changes the local ap_cur, st_cur and na_cur variables and should be
	 * the last check before the actual write */
	if (caplen < 24 && caplen >= 10 && h80211[0])
	{
		/* RTS || CTS || ACK || CF-END || CF-END&CF-ACK*/
		//(h80211[0] == 0xB4 || h80211[0] == 0xC4 || h80211[0] == 0xD4 ||
		// h80211[0] == 0xE4 || h80211[0] == 0xF4)

		/* use general control frame detection, as the structure is always the
		 * same: mac(s) starting at [4] */
		if (h80211[0] & 0x04)
		{
			p = h80211 + 4;
			while (p <= h80211 + 16 && p <= h80211 + caplen)
			{
				MAC_ADDRESS_COPY(&namac, (mac_address *)p);

                if (MAC_ADDRESS_IS_EMPTY(&namac))
				{
                    p += sizeof namac;
					continue;
				}

                if (MAC_ADDRESS_IS_BROADCAST(&namac))
				{
                    p += sizeof namac;
					continue;
				}

				if (lopt.hide_known)
				{
					/* Check AP list. */
					ap_cur = ap_info_lookup(&lopt.ap_list[lopt.current_ap_list_index], &namac);

					/* If it's an AP, try next mac */
					if (ap_cur != NULL)
					{
                        p += sizeof namac;
						continue;
					}

					/* check STA list */
					st_cur = sta_info_lookup(&lopt.sta_list[lopt.current_sta_list_index], &namac);

					/* If it's a client, try next mac */
					if (st_cur != NULL)
					{
                        p += sizeof namac;
						continue;
					}
				}

				/* Not found in either AP list or ST list, look through NA list
				 */
				struct NA_info * na_cur;

				na_cur = na_info_lookup(&lopt.na_list, &namac);

				/* update our chained list of unknown stations */
				/* if it's a new mac, add it */

				if (na_cur == NULL)
				{
                    na_cur = calloc(1, sizeof *na_cur);
					if (na_cur == NULL)
					{
						perror("calloc failed");
						return 1;
					}

                    MAC_ADDRESS_COPY(&na_cur->namac, &namac);

					gettimeofday(&na_cur->tv, NULL);
					na_cur->tinit = time(NULL);
					na_cur->tlast = time(NULL);

					na_cur->power = -1;
					na_cur->channel = -1;
					na_cur->ack = 0;
					na_cur->ack_old = 0;
					na_cur->ackps = 0;
					na_cur->cts = 0;
					na_cur->rts_r = 0;
					na_cur->rts_t = 0;

					TAILQ_INSERT_TAIL(&lopt.na_list, na_cur, entry);
                }

				/* update the last time seen & power*/

				na_cur->tlast = time(NULL);
				na_cur->power = ri->ri_power;
				na_cur->channel = ri->ri_channel;

				switch (h80211[0] & 0xF0)
				{
					case 0xB0:
						if (p == h80211 + 4) na_cur->rts_r++;
						if (p == h80211 + 10) na_cur->rts_t++;
						break;

					case 0xC0:
						na_cur->cts++;
						break;

					case 0xD0:
						na_cur->ack++;
						break;

					default:
						na_cur->other++;
						break;
				}

				/*grab next mac (for rts frames)*/
                p += sizeof namac;
			}
		}
	}

	if (opt.f_cap != NULL && caplen >= 10)
	{
		pkh.len = pkh.caplen = (uint32_t) caplen;

		gettimeofday(&tv, NULL);

		pkh.tv_sec = (int32_t) tv.tv_sec;
		pkh.tv_usec = (int32_t)((tv.tv_usec & ~0x1ff) + ri->ri_power + 64);

		n = sizeof(pkh);

		if (fwrite(&pkh, 1, n, opt.f_cap) != (size_t) n)
		{
			perror("fwrite(packet header) failed");
			return (1);
		}

        fflush(opt.f_cap);

		n = pkh.caplen;

		if (fwrite(h80211, 1, n, opt.f_cap) != (size_t) n)
		{
			perror("fwrite(packet data) failed");
			return (1);
		}

        fflush(opt.f_cap);
	}

	return (0);
}

static void sort_aps(struct local_options * const options)
{
    time_t tt = time(NULL);
	size_t const sorted_list_index = 
		(options->current_ap_list_index + 1) & 1;

    /* Sort the aps by WHATEVER first, */
    /* Can't 'sort' be used to sort these entries? */

	TAILQ_INIT(&lopt.ap_list[sorted_list_index]);

	while (TAILQ_FIRST(&options->ap_list[options->current_ap_list_index]) != NULL)
    {
		struct AP_info * ap_cur;
        struct AP_info * ap_min = NULL;

		/* Only the most recent entries are sorted. */
		TAILQ_FOREACH(ap_cur, &options->ap_list[options->current_ap_list_index], entry)
        {
			if (tt - ap_cur->tlast > 20)
			{
                ap_min = ap_cur;
			}
        }

        if (ap_min == NULL)
        {
			ap_min = TAILQ_FIRST(&options->ap_list[options->current_ap_list_index]);

/* 
#define SORT_BY_BSSID	1
#define SORT_BY_POWER	2
#define SORT_BY_BEACON	3
#define SORT_BY_DATA	4
#define SORT_BY_PRATE	6
#define SORT_BY_CHAN	7
#define	SORT_BY_MBIT	8
#define SORT_BY_ENC	9
#define SORT_BY_CIPHER	10
#define SORT_BY_AUTH	11
#define SORT_BY_ESSID	12
*/

			TAILQ_FOREACH(ap_cur, &options->ap_list[options->current_ap_list_index], entry)
			{
				if (ap_min == ap_cur)
				{
					/* There's no point in comparing an entry with itself. */
					continue;
				}

				switch (options->sort_by)
				{
					case SORT_BY_BSSID:
						if (MAC_ADDRESS_COMPARE(&ap_cur->bssid, &ap_min->bssid)
							* options->sort_inv
							< 0)
							ap_min = ap_cur;
						break;
					case SORT_BY_POWER:
						if ((ap_cur->avg_power - ap_min->avg_power)
							* options->sort_inv
							< 0)
							ap_min = ap_cur;
						break;
					case SORT_BY_BEACON:
						if ((ap_cur->nb_bcn < ap_min->nb_bcn) && options->sort_inv)
							ap_min = ap_cur;
						break;
					case SORT_BY_DATA:
						if ((ap_cur->nb_data < ap_min->nb_data)
							&& options->sort_inv)
							ap_min = ap_cur;
						break;
					case SORT_BY_PRATE:
						if ((ap_cur->nb_dataps - ap_min->nb_dataps)
							* options->sort_inv
							< 0)
							ap_min = ap_cur;
						break;
					case SORT_BY_CHAN:
						if ((ap_cur->channel - ap_min->channel) * options->sort_inv
							< 0)
							ap_min = ap_cur;
						break;
					case SORT_BY_MBIT:
						if ((ap_cur->max_speed - ap_min->max_speed)
							* options->sort_inv
							< 0)
							ap_min = ap_cur;
						break;
					case SORT_BY_ENC:
						if (((int)(ap_cur->security & STD_FIELD)
							 - (int)(ap_min->security & STD_FIELD))
							* options->sort_inv
							< 0)
							ap_min = ap_cur;
						break;
					case SORT_BY_CIPHER:
						if (((int)(ap_cur->security & ENC_FIELD)
							 - (int)(ap_min->security & ENC_FIELD))
							* options->sort_inv
							< 0)
							ap_min = ap_cur;
						break;
					case SORT_BY_AUTH:
						if (((int)(ap_cur->security & AUTH_FIELD)
							 - (int)(ap_min->security & AUTH_FIELD))
							* options->sort_inv
							< 0)
							ap_min = ap_cur;
						break;
					case SORT_BY_ESSID:
						if ((strncasecmp((char *)ap_cur->essid,
										 (char *)ap_min->essid,
										 ESSID_LENGTH))
							* options->sort_inv
							< 0)
							ap_min = ap_cur;
						break;
					default: // sort by power
						if (ap_cur->avg_power < ap_min->avg_power)
							ap_min = ap_cur;
						break;
				}
			}
        }

		TAILQ_REMOVE(&options->ap_list[options->current_ap_list_index], ap_min, entry);
		TAILQ_INSERT_TAIL(&options->ap_list[sorted_list_index], ap_min, entry);
    }

	/* Start using the sorted list. */
	options->current_ap_list_index = sorted_list_index;
}

static void sort_stas(struct local_options * const options)
{
    time_t tt = time(NULL);
	size_t const sorted_list_index = (options->current_sta_list_index + 1) & 1;

	TAILQ_INIT(&options->sta_list[sorted_list_index]);

	while (TAILQ_FIRST(&options->sta_list[options->current_sta_list_index]) != NULL)
    {
		struct ST_info * st_cur = TAILQ_FIRST(&options->sta_list[options->current_sta_list_index]);
        struct ST_info * st_min = NULL;

		/* Don't sort entries older than 60 seconds. */
		TAILQ_FOREACH(st_cur, &options->sta_list[options->current_sta_list_index], entry)
        {
			if (tt - st_cur->tlast > 60)
			{
                st_min = st_cur;
			}
        }

        if (st_min == NULL)
        {
			st_min = TAILQ_FIRST(&options->sta_list[options->current_sta_list_index]); 

			TAILQ_FOREACH(st_cur, &options->sta_list[options->current_sta_list_index], entry)
            {
				if (st_min == st_cur)
				{
					/* There's no point in comparing an entry with itself. */
					continue;
				}
				if (st_cur->power < st_min->power)
				{
                    st_min = st_cur;
				}
            }
        }

		TAILQ_REMOVE(&options->sta_list[options->current_sta_list_index], st_min, entry);
		TAILQ_INSERT_TAIL(&options->sta_list[sorted_list_index], st_min, entry);
    }

	options->current_sta_list_index = sorted_list_index;
}

static void dump_sort(void)
{
    sort_aps(&lopt);
    sort_stas(&lopt);
}

static int getBatteryState(void) { return get_battery_state(); }

static char * getStringTimeFromSec(double seconds)
{
	int hour[3];
	char * ret;
	char * HourTime;
	char * MinTime;

	if (seconds < 0) return (NULL);

	ret = calloc(256, sizeof *ret);
	ALLEGE(ret != NULL);

	HourTime = calloc(128, sizeof *HourTime);
	ALLEGE(HourTime != NULL);
	MinTime = calloc(128, sizeof MinTime);
	ALLEGE(MinTime != NULL);

	hour[0] = (int) (seconds);
	hour[1] = hour[0] / 60;
	hour[2] = hour[1] / 60;
	hour[0] %= 60;
	hour[1] %= 60;

	if (hour[2] != 0)
		snprintf(
			HourTime, 128, "%d %s", hour[2], (hour[2] == 1) ? "hour" : "hours");
	if (hour[1] != 0)
		snprintf(
			MinTime, 128, "%d %s", hour[1], (hour[1] == 1) ? "min" : "mins");

	if (hour[2] != 0 && hour[1] != 0)
		snprintf(ret, 256, "%s %s", HourTime, MinTime);
	else
	{
		if (hour[2] == 0 && hour[1] == 0)
			snprintf(ret, 256, "%d s", hour[0]);
		else
			snprintf(ret, 256, "%s", (hour[2] == 0) ? MinTime : HourTime);
	}

	free(MinTime);
	free(HourTime);

	return (ret);
}

static char * getBatteryString(void)
{
	int batt_time;
	char * ret;
	char * batt_string;

	batt_time = getBatteryState();

	if (batt_time <= 60)
	{
		ret = calloc(2, sizeof *ret);
		ALLEGE(ret != NULL);
		ret[0] = ']';
		return ret;
	}

	batt_string = getStringTimeFromSec((double) batt_time);
	ALLEGE(batt_string != NULL);

	ret = calloc(256, sizeof *ret);
	ALLEGE(ret != NULL);

	snprintf(ret, 256, "][ BAT: %s ]", batt_string);

	free(batt_string);

	return (ret);
}

#define TSTP_SEC                                                               \
	1000000ULL /* It's a 1 MHz clock, so a million ticks per second! */
#define TSTP_MIN (TSTP_SEC * 60ULL)
#define TSTP_HOUR (TSTP_MIN * 60ULL)
#define TSTP_DAY (TSTP_HOUR * 24ULL)

static char * parse_timestamp(unsigned long long timestamp)
{
#define TSTP_LEN 15
	static char s[TSTP_LEN];
	unsigned long long rem;
	unsigned char days, hours, mins, secs;

	// Initialize array
	memset(s, 0, sizeof s);

	// Calculate days, hours, mins and secs
	days = (uint8_t)(timestamp / TSTP_DAY);
	rem = timestamp % TSTP_DAY;
	hours = (unsigned char) (rem / TSTP_HOUR);
	rem %= TSTP_HOUR;
	mins = (unsigned char) (rem / TSTP_MIN);
	rem %= TSTP_MIN;
	secs = (unsigned char) (rem / TSTP_SEC);

	snprintf(s, TSTP_LEN, "%3ud %02u:%02u:%02u", days, hours, mins, secs);
#undef TSTP_LEN

	return (s);
}

static int IsAp2BeSkipped(struct AP_info * ap_cur)
{
	REQUIRE(ap_cur != NULL);

	if (ap_cur->nb_pkt < lopt.min_pkts
		|| (time(NULL) - ap_cur->tlast) > lopt.berlin
		|| MAC_ADDRESS_IS_BROADCAST(&ap_cur->bssid))
	{
		return (1);
	}

	if (ap_cur->security != 0 && lopt.f_encrypt != 0
		&& ((ap_cur->security & lopt.f_encrypt) == 0))
	{
		return (1);
	}

	if (is_filtered_essid(ap_cur->essid))
	{
		return (1);
	}

	return (0);
}

#define CHECK_END_OF_SCREEN()                                                  \
	do                                                                         \
	{                                                                          \
		++nlines;                                                              \
		if (nlines >= (ws_row - 1))                                            \
		{                                                                      \
			erase_display(0);                                                  \
			return;                                                            \
		};                                                                     \
	} while (0)

static void dump_print(int ws_row, int ws_col, int if_num)
{
	time_t tt;
	struct tm * lt;
	int nlines, i, n;
	char strbuf[512];
	char buffer[512];
	char ssid_list[512];
	struct AP_info * ap_cur;
	struct ST_info * st_cur;
	struct NA_info * na_cur;
	int columns_ap = 83;
	int columns_sta = 74;
	int columns_na = 68;
	ssize_t len;

	int num_ap;
	int num_sta;

	if (opt.output_format_wifi_scanner)
	{
		return;
	}

	if (!lopt.singlechan)
	{
		columns_ap -= 4; // no RXQ in scan mode
	}

	if (lopt.show_uptime)
	{
		columns_ap += 15; // show uptime needs more space
	}

	nlines = 2;

    if (nlines >= ws_row)
    {
        return;
    }

	if (lopt.do_sort_always)
	{
        acquire_sort_lock(&lopt);

		dump_sort();

		release_sort_lock(&lopt);
	}

	tt = time(NULL);
	lt = localtime(&tt);

	if (lopt.is_berlin)
	{
		lopt.maxaps = 0;
		lopt.numaps = 0;

		TAILQ_FOREACH_REVERSE(ap_cur, &lopt.ap_list[lopt.current_ap_list_index], ap_list_head, entry)
		{
			lopt.maxaps++;
			if (ap_cur->nb_pkt < 2 
                || (time(NULL) - ap_cur->tlast) > lopt.berlin
				|| MAC_ADDRESS_IS_BROADCAST(&ap_cur->bssid))
			{
				continue;
			}
			lopt.numaps++;
		}

		if (lopt.numaps > lopt.maxnumaps)
		{
			lopt.maxnumaps = lopt.numaps;
		}
	}

	/*
	 *  display the channel, battery, position (if we are connected to GPSd)
	 *  and current time
	 */

    moveto(1, 2);
	textcolor_normal();
	textcolor_fg(TEXT_WHITE);

	if (lopt.freqoption)
	{
		snprintf(strbuf, sizeof(strbuf) - 1, " Freq %4d", lopt.frequency[0]);
		for (i = 1; i < if_num; i++)
		{
			memset(buffer, '\0', sizeof(buffer));
			snprintf(buffer, sizeof(buffer), ",%4d", lopt.frequency[i]);
			strncat(strbuf, buffer, sizeof(strbuf) - strlen(strbuf) - 1);
		}
	}
	else
	{
		snprintf(strbuf, sizeof(strbuf) - 1, " CH %2d", lopt.channel[0]);
		for (i = 1; i < if_num; i++)
		{
			memset(buffer, '\0', sizeof(buffer));
			snprintf(buffer, sizeof(buffer), ",%2d", lopt.channel[i]);
			strncat(strbuf, buffer, sizeof(strbuf) - strlen(strbuf) - 1);
		}
	}

    buffer[0] = '\0'; 

	if (lopt.gps_loc[0] || (opt.usegpsd))
	{
		// If using GPS then check if we have a valid fix or not and report accordingly
		if (lopt.gps_loc[0] != 0) //-V550
		{
			struct tm * gtime = &lopt.gps_time;
			snprintf(buffer,
					 sizeof(buffer) - 1,
					 " %s[ GPS %3.6f,%3.6f %02d:%02d:%02d ][ Elapsed: %s ][ "
					 "%04d-%02d-%02d %02d:%02d ",
					 lopt.batt,
					 lopt.gps_loc[0],
					 lopt.gps_loc[1],
					 gtime->tm_hour,
					 gtime->tm_min,
					 gtime->tm_sec,
					 lopt.elapsed_time,
					 1900 + lt->tm_year,
					 1 + lt->tm_mon,
					 lt->tm_mday,
					 lt->tm_hour,
					 lt->tm_min);
		}
		else
		{
			snprintf(
				buffer,
				sizeof(buffer) - 1,
				" %s[ GPS %-29s ][ Elapsed: %s ][ %04d-%02d-%02d %02d:%02d ",
				lopt.batt,
				" *** No Fix! ***",
				lopt.elapsed_time,
				1900 + lt->tm_year,
				1 + lt->tm_mon,
				lt->tm_mday,
				lt->tm_hour,
				lt->tm_min);
		}
	}
	else
	{
		snprintf(buffer,
				 sizeof(buffer) - 1,
				 " %s[ Elapsed: %s ][ %04d-%02d-%02d %02d:%02d ",
				 lopt.batt,
				 lopt.elapsed_time,
				 1900 + lt->tm_year,
				 1 + lt->tm_mon,
				 lt->tm_mday,
				 lt->tm_hour,
				 lt->tm_min);
	}

	strncat(strbuf, buffer, (512 - strlen(strbuf) - 1));
    buffer[0] = '\0';
    
	if (lopt.is_berlin)
	{
		snprintf(buffer,
				 sizeof(buffer) - 1,
				 " ][%3d/%3d/%4d ",
				 lopt.numaps,
				 lopt.maxnumaps,
				 lopt.maxaps);
	}
    /* FIXME - Don't use strncat. */
	strncat(strbuf, buffer, (512 - strlen(strbuf) - 1));

    buffer[0] = '\0'; 

	if (strlen(lopt.message) > 0)
	{
		strncat(strbuf, lopt.message, (512 - strlen(strbuf) - 1));
	}

	strbuf[ws_col - 1] = '\0';

	ALLEGE(strchr(strbuf, '\n') == NULL);
	console_puts(strbuf);
	CHECK_END_OF_SCREEN();

	/* print some information about each detected AP */

	erase_line(0);
	move(CURSOR_DOWN, 1);
	CHECK_END_OF_SCREEN();

	if (lopt.show_ap)
	{
		strbuf[0] = 0;
		strcat(strbuf, " BSSID              PWR ");

		if (lopt.singlechan) strcat(strbuf, "RXQ ");

		strcat(strbuf, " Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ");

		if (lopt.show_uptime) strcat(strbuf, "        UPTIME ");

		if (lopt.show_wps)
		{
            /* FIXME: Clean up all this output. */
			strcat(strbuf, "WPS   ");
			if (ws_col > (columns_ap - 4))
			{
				memset(strbuf + strlen(strbuf),
					   ' ',
					   sizeof(strbuf) - strlen(strbuf) - 1);
				snprintf(strbuf + columns_ap + lopt.maxsize_wps_seen - 5,
						 8,
						 "%s",
						 "  ESSID");
				if (lopt.show_manufacturer)
				{
					memset(strbuf + columns_ap + lopt.maxsize_wps_seen + 1,
						   ' ',
						   sizeof(strbuf) - columns_ap - lopt.maxsize_wps_seen
							   - 1);
					snprintf(strbuf + columns_ap + lopt.maxsize_wps_seen
								 + lopt.maxsize_essid_seen
								 - 4,
							 15,
							 "%s",
							 "MANUFACTURER");
				}
			}
		}
		else
		{
			strcat(strbuf, "ESSID");

			if (lopt.show_manufacturer && (ws_col > (columns_ap - 4)))
			{
				// write spaces (32).
				memset(strbuf + columns_ap, ' ', lopt.maxsize_essid_seen - 5);
				snprintf(strbuf + columns_ap + lopt.maxsize_essid_seen - 7,
						 15,
						 "%s",
						 "  MANUFACTURER");
			}
		}
		strbuf[ws_col - 1] = '\0';
		console_puts(strbuf);
		CHECK_END_OF_SCREEN();

		erase_line(0);
		move(CURSOR_DOWN, 1);
		CHECK_END_OF_SCREEN();

		num_ap = 0;

		TAILQ_FOREACH_REVERSE(ap_cur, &lopt.ap_list[lopt.current_ap_list_index], ap_list_head, entry)
		{
			/* skip APs with only one packet, or those older than 2 min.
			 * always skip if bssid == broadcast*  
			 */
			if (IsAp2BeSkipped(ap_cur))
			{
				if (lopt.p_selected_ap == ap_cur)
				{ //the selected AP is skipped (will not be printed), we have to go to the next printable AP
					struct AP_info * ap_tmp;

					if (selection_direction_up == lopt.en_selection_direction)
					{
						//UP arrow was last pressed
						ap_tmp = TAILQ_NEXT(ap_cur, entry);
						if (ap_tmp != NULL)
						{
							while ((NULL != (lopt.p_selected_ap = ap_tmp))
								   && IsAp2BeSkipped(ap_tmp))
							{
								ap_tmp = TAILQ_NEXT(ap_tmp, entry);
							}
						}
						if (ap_tmp == NULL) //we have reached the first element in the list, so go in another direction
						{ //upon we have an AP that is not skipped
							ap_tmp = TAILQ_PREV(ap_cur, ap_list_head, entry);
							if (ap_tmp != NULL)
							{
								while ((NULL != (lopt.p_selected_ap = ap_tmp))
									   && IsAp2BeSkipped(ap_tmp))
									ap_tmp = TAILQ_PREV(ap_tmp, ap_list_head, entry);
							}
						}
					}
					else if (selection_direction_down == lopt.en_selection_direction)
					{
						//DOWN arrow was last pressed
						ap_tmp = TAILQ_PREV(ap_cur, ap_list_head, entry); 
						if (ap_tmp != NULL)
						{
							while ((NULL != (lopt.p_selected_ap = ap_tmp))
								   && IsAp2BeSkipped(ap_tmp))
							{
								ap_tmp = TAILQ_PREV(ap_tmp, ap_list_head, entry); 
							}
						}
						if (ap_tmp == NULL) //we have reached the last element in the list, so go in another direction
						{ //upon we have an AP that is not skipped
							ap_tmp = TAILQ_NEXT(ap_cur, entry); 
							if (ap_tmp != NULL)
							{
								while ((NULL != (lopt.p_selected_ap = ap_tmp))
									   && IsAp2BeSkipped(ap_tmp))
									ap_tmp = TAILQ_NEXT(ap_tmp, entry); 
							}
						}
					}
				}
				continue;
			}

			num_ap++;

			if (num_ap < lopt.start_print_ap)
			{
				continue;
			}

			nlines++;

			if (nlines > (ws_row - 1)) return;

			snprintf(strbuf,
					 sizeof(strbuf),
					 " %02X:%02X:%02X:%02X:%02X:%02X",
					 ap_cur->bssid.addr[0],
                     ap_cur->bssid.addr[1],
                     ap_cur->bssid.addr[2],
                     ap_cur->bssid.addr[3],
                     ap_cur->bssid.addr[4],
                     ap_cur->bssid.addr[5]);

			len = strlen(strbuf);

			if (lopt.singlechan)
			{
				snprintf(strbuf + len,
						 sizeof(strbuf) - len,
						 "  %3d %3d %8lu %8lu %4d",
						 ap_cur->avg_power,
						 ap_cur->rx_quality,
						 ap_cur->nb_bcn,
						 ap_cur->nb_data,
						 ap_cur->nb_dataps);
			}
			else
			{
				snprintf(strbuf + len,
						 sizeof(strbuf) - len,
						 "  %3d %8lu %8lu %4d",
						 ap_cur->avg_power,
						 ap_cur->nb_bcn,
						 ap_cur->nb_data,
						 ap_cur->nb_dataps);
			}

			len = strlen(strbuf);

			if (ap_cur->standard[0])
			{
				// In case of 802.11n or 802.11ac, QoS is pretty much implied
				// Short or long preamble is not that useful anymore.
				snprintf(strbuf + len,
						 sizeof(strbuf) - len,
						 " %3d %4d   ",
						 ap_cur->channel,
						 ap_cur->max_speed);
			}
			else
			{
				snprintf(strbuf + len,
						 sizeof(strbuf) - len,
						 " %3d %4d%c%c ",
						 ap_cur->channel,
						 ap_cur->max_speed,
						 (ap_cur->security & STD_QOS) ? 'e' : ' ',
						 (ap_cur->preamble) ? '.' : ' ');
			}

			len = strlen(strbuf);

			if ((ap_cur->security & STD_FIELD) == 0)
				snprintf(strbuf + len, sizeof(strbuf) - len, "    ");
			else
			{
				if (ap_cur->security & STD_WPA2)
				{
					if (ap_cur->security & AUTH_SAE
						|| ap_cur->security & AUTH_OWE)
						snprintf(strbuf + len, sizeof(strbuf) - len, "WPA3");
					else
						snprintf(strbuf + len, sizeof(strbuf) - len, "WPA2");
				}
				else if (ap_cur->security & STD_WPA)
					snprintf(strbuf + len, sizeof(strbuf) - len, "WPA ");
				else if (ap_cur->security & STD_WEP)
					snprintf(strbuf + len, sizeof(strbuf) - len, "WEP ");
				else if (ap_cur->security & STD_OPN)
					snprintf(strbuf + len, sizeof(strbuf) - len, "OPN ");
			}

			strncat(strbuf, " ", sizeof(strbuf) - strlen(strbuf) - 1);

			len = strlen(strbuf);

			if ((ap_cur->security & ENC_FIELD) == 0)
				snprintf(strbuf + len, sizeof(strbuf) - len, "       ");
			else
			{
				if (ap_cur->security & ENC_CCMP)
					snprintf(strbuf + len, sizeof(strbuf) - len, "CCMP   ");
				else if (ap_cur->security & ENC_WRAP)
					snprintf(strbuf + len, sizeof(strbuf) - len, "WRAP   ");
				else if (ap_cur->security & ENC_TKIP)
					snprintf(strbuf + len, sizeof(strbuf) - len, "TKIP   ");
				else if (ap_cur->security & ENC_WEP104)
					snprintf(strbuf + len, sizeof(strbuf) - len, "WEP104 ");
				else if (ap_cur->security & ENC_WEP40)
					snprintf(strbuf + len, sizeof(strbuf) - len, "WEP40  ");
				else if (ap_cur->security & ENC_WEP)
					snprintf(strbuf + len, sizeof(strbuf) - len, "WEP    ");
			}

			len = strlen(strbuf);

			if ((ap_cur->security & AUTH_FIELD) == 0)
				snprintf(strbuf + len, sizeof(strbuf) - len, "    ");
			else
			{
				if (ap_cur->security & AUTH_SAE)
					snprintf(strbuf + len, sizeof(strbuf) - len, "SAE ");
				else if (ap_cur->security & AUTH_MGT)
					snprintf(strbuf + len, sizeof(strbuf) - len, "MGT ");
				else if (ap_cur->security & AUTH_CMAC)
					snprintf(strbuf + len, sizeof(strbuf) - len, "CMAC");
				else if (ap_cur->security & AUTH_PSK)
				{
					if (ap_cur->security & STD_WEP)
						snprintf(strbuf + len, sizeof(strbuf) - len, "SKA ");
					else
						snprintf(strbuf + len, sizeof(strbuf) - len, "PSK ");
				}
				else if (ap_cur->security & AUTH_OWE)
					snprintf(strbuf + len, sizeof(strbuf) - len, "OWE ");
				else if (ap_cur->security & AUTH_OPN)
					snprintf(strbuf + len, sizeof(strbuf) - len, "OPN ");
			}

			len = strlen(strbuf);

			if (lopt.show_uptime)
			{
				snprintf(strbuf + len,
						 sizeof(strbuf) - len,
						 " %14s",
						 parse_timestamp(ap_cur->timestamp));
				len = strlen(strbuf);
			}

			if (lopt.p_selected_ap && (lopt.p_selected_ap == ap_cur))
			{
				if (lopt.mark_cur_ap)
				{
					if (ap_cur->marked == 0)
					{
						ap_cur->marked = 1;
					}
					else
					{
						ap_cur->marked_color++;
						if (ap_cur->marked_color > TEXT_MAX_COLOR)
						{
							ap_cur->marked_color = 1;
							ap_cur->marked = 0;
						}
					}
					lopt.mark_cur_ap = 0;
				}
				textstyle(TEXT_REVERSE);
				MAC_ADDRESS_COPY(&lopt.selected_bssid, &ap_cur->bssid);
			}

			if (ap_cur->marked)
			{
				textcolor_fg(ap_cur->marked_color);
			}

			memset(strbuf + len, ' ', sizeof(strbuf) - len - 1);

			if (ws_col > (columns_ap - 4))
			{
				if (lopt.show_wps)
				{
					ssize_t wps_len = len;

					if (ap_cur->wps.state != 0xFF)
					{
						if (ap_cur->wps.ap_setup_locked) // AP setup locked
							snprintf(
								strbuf + len, sizeof(strbuf) - len, "Locked");
						else
						{
							snprintf(strbuf + len,
									 sizeof(strbuf) - len,
									 " %u.%d",
									 ap_cur->wps.version >> 4,
									 ap_cur->wps.version & 0xF); // Version
							len = strlen(strbuf);
							if (ap_cur->wps.meth) // WPS Config Methods
							{
								char tbuf[64];
								tbuf[0] = '\0';
								int sep = 0;
#define T(bit, name)                                                           \
	do                                                                         \
	{                                                                          \
		if (ap_cur->wps.meth & (1u << (bit)))                                  \
		{                                                                      \
			if (sep) strcat(tbuf, ",");                                        \
			sep = 1;                                                           \
			strncat(tbuf, (name), (64 - strlen(tbuf) - 1));                    \
		}                                                                      \
	} while (0)
								T(0u, "USB"); // USB method
								T(1u, "ETHER"); // Ethernet
								T(2u, "LAB"); // Label
								T(3u, "DISP"); // Display
								T(4u, "EXTNFC"); // Ext. NFC Token
								T(5u, "INTNFC"); // Int. NFC Token
								T(6u, "NFCINTF"); // NFC Interface
								T(7u, "PBC"); // Push Button
								T(8u, "KPAD"); // Keypad
								snprintf(strbuf + len,
										 sizeof(strbuf) - len,
										 " %s",
										 tbuf);
#undef T
							}
						}
					}
					else
					{
						snprintf(strbuf + len, sizeof(strbuf) - len, " ");
					}
					len = strlen(strbuf);

					if ((ssize_t)lopt.maxsize_wps_seen <= len - wps_len)
					{
						lopt.maxsize_wps_seen = (u_int) MAX(len - wps_len, 6);
					}
					else
					{
						// pad output
						memset(strbuf + len, ' ', sizeof(strbuf) - len - 1);
						len += lopt.maxsize_wps_seen - (len - wps_len);
						strbuf[len] = '\0';
					}
				}

				ssize_t essid_len = len;

				if (ap_cur->essid[0] != 0x00)
				{
					if (lopt.show_wps)
						snprintf(strbuf + len,
								 sizeof(strbuf) - len - 1,
								 "  %s",
								 ap_cur->essid);
					else
						snprintf(strbuf + len,
								 sizeof(strbuf) - len,
								 " %s",
								 ap_cur->essid);
				}
				else
				{
					if (lopt.show_wps)
						snprintf(strbuf + len,
								 sizeof(strbuf) - len - 1,
								 "  <length:%3d>%s",
								 ap_cur->ssid_length,
								 "\x00");
					else
						snprintf(strbuf + len,
								 sizeof(strbuf) - len,
								 " <length:%3d>%s",
								 ap_cur->ssid_length,
								 "\x00");
				}
				len = strlen(strbuf);

				if (lopt.show_manufacturer)
				{
					if (lopt.maxsize_essid_seen <= len - essid_len)
						lopt.maxsize_essid_seen
							= (u_int) MAX(len - essid_len, 5);
					else
					{
						// pad output
						memset(strbuf + len, ' ', sizeof(strbuf) - len - 1);
						len += lopt.maxsize_essid_seen - (len - essid_len);
						strbuf[len] = '\0';
					}

					if (ap_cur->manuf == NULL)
						ap_cur->manuf = get_manufacturer(ap_cur->bssid.addr[0],
                                                         ap_cur->bssid.addr[1],
                                                         ap_cur->bssid.addr[2]);

					snprintf(strbuf + len,
							 sizeof(strbuf) - len - 1,
							 " %s",
							 ap_cur->manuf);
				}
			}

			len = strlen(strbuf);

			// write spaces (32) until the end of column
			memset(strbuf + len, ' ', (size_t) ws_col - 1);

			strbuf[ws_col - 1] = '\0';
			console_puts(strbuf);

			if ((lopt.p_selected_ap && (lopt.p_selected_ap == ap_cur))
				|| (ap_cur->marked))
			{
				textstyle(TEXT_RESET);
			}
		}

		/* print some information about each detected station */

		erase_line(0);
		move(CURSOR_DOWN, 1);
		CHECK_END_OF_SCREEN();
	}

	if (lopt.show_sta)
	{
		strcpy(strbuf,
			   " BSSID              STATION "
			   "           PWR   Rate    Lost    Frames  Notes  Probes");
		strbuf[ws_col - 1] = '\0';
		console_puts(strbuf);
		CHECK_END_OF_SCREEN();

		erase_line(0);
		move(CURSOR_DOWN, 1);
		CHECK_END_OF_SCREEN();

		num_sta = 0;

		TAILQ_FOREACH_REVERSE(ap_cur, &lopt.ap_list[lopt.current_ap_list_index], ap_list_head, entry)
		{
			if (ap_cur->nb_pkt < 2 
				|| (time(NULL) - ap_cur->tlast) > lopt.berlin)
			{
				continue;
			}

			if (ap_cur->security != 0 && lopt.f_encrypt != 0
				&& ((ap_cur->security & lopt.f_encrypt) == 0))
			{
				continue;
			}

			// Don't filter unassociated clients by ESSID
			if (!MAC_ADDRESS_IS_BROADCAST(&ap_cur->bssid)
				&& is_filtered_essid(ap_cur->essid))
			{
				continue;
			}

			if (nlines >= (ws_row - 1))
			{
				return;
			}

			if (lopt.p_selected_ap
				&& MAC_ADDRESS_EQUAL(&lopt.selected_bssid, &ap_cur->bssid))
			{
				textstyle(TEXT_REVERSE);
			}

			if (ap_cur->marked)
			{
				textcolor_fg(ap_cur->marked_color);
			}

			TAILQ_FOREACH_REVERSE(st_cur, &lopt.sta_list[lopt.current_sta_list_index], sta_list_head, entry)
			{
				if (st_cur->base != ap_cur
					|| (time(NULL) - st_cur->tlast) > lopt.berlin)
				{
					continue;
				}

				if (MAC_ADDRESS_IS_BROADCAST(&ap_cur->bssid)
                    && lopt.asso_client)
				{
					continue;
				}

				num_sta++;

				if (lopt.start_print_sta > num_sta)
				{
					continue;
				}

				nlines++;

				if (nlines >= (ws_row - 1)) return;

                if (MAC_ADDRESS_IS_BROADCAST(&ap_cur->bssid))
                {
					printf(" (not associated) ");
                }
                else
                {
					printf(" %02X:%02X:%02X:%02X:%02X:%02X",
                           ap_cur->bssid.addr[0],
                           ap_cur->bssid.addr[1],
                           ap_cur->bssid.addr[2],
                           ap_cur->bssid.addr[3],
                           ap_cur->bssid.addr[4],
                           ap_cur->bssid.addr[5]);
                }

				printf("  %02X:%02X:%02X:%02X:%02X:%02X",
					   st_cur->stmac.addr[0],
					   st_cur->stmac.addr[1],
					   st_cur->stmac.addr[2],
					   st_cur->stmac.addr[3],
					   st_cur->stmac.addr[4],
					   st_cur->stmac.addr[5]);

				printf("  %3d ", st_cur->power);
				printf("  %2d", st_cur->rate_to / 1000000);
				printf("%c", (st_cur->qos_fr_ds) ? 'e' : ' ');
				printf("-%2d", st_cur->rate_from / 1000000);
				printf("%c", (st_cur->qos_to_ds) ? 'e' : ' ');
				printf("  %4d", st_cur->missed);
				printf(" %8lu", st_cur->nb_pkt);
				printf("  %-5s",
					   (st_cur->wpa.pmkid[0] != 0)
						   ? "PMKID"
						   : (st_cur->wpa.state == 7 ? "EAPOL" : ""));

				if (ws_col > (columns_sta - 6))
				{
					memset(ssid_list, 0, sizeof(ssid_list));

					for (i = 0, n = 0; i < NB_PRB; i++)
					{
						if (st_cur->probes[i][0] == '\0') continue;

						snprintf(ssid_list + n,
								 sizeof(ssid_list) - n - 1,
								 "%c%s",
								 (i > 0) ? ',' : ' ',
								 st_cur->probes[i]);

						n += (1 + strlen(st_cur->probes[i]));

						if (n >= (int) sizeof(ssid_list)) break;
					}

					snprintf(strbuf, sizeof(strbuf) - 1, "%-256s", ssid_list)
							< 0
						? abort()
						: (void) 0;
					strbuf[MAX(ws_col - 75, 0)] = '\0';
					printf(" %s", strbuf);
				}

				erase_line(0);
				putchar('\n');
			}

			if ((lopt.p_selected_ap
				 && MAC_ADDRESS_EQUAL(&lopt.selected_bssid, &ap_cur->bssid))
				|| (ap_cur->marked))
			{
				textstyle(TEXT_RESET);
			}
		}
	}

	if (lopt.show_ack)
	{
		/* print some information about each unknown station */

		erase_line(0);
		move(CURSOR_DOWN, 1);
		CHECK_END_OF_SCREEN();

		memcpy(strbuf,
			   " MAC       "
			   "          CH PWR    ACK ACK/s    CTS RTS_RX RTS_TX  OTHER",
			   (size_t) columns_na);
		strbuf[ws_col - 1] = '\0';
		console_puts(strbuf);
		CHECK_END_OF_SCREEN();

		memset(strbuf, ' ', (size_t) ws_col - 1);
		strbuf[ws_col - 1] = '\0';
		console_puts(strbuf);
		CHECK_END_OF_SCREEN();

		TAILQ_FOREACH(na_cur, &lopt.na_list, entry)
		{
			if (time(NULL) - na_cur->tlast > 120)
			{
				continue;
			}

			nlines++;

			if (nlines >= (ws_row - 1))
			{
				return;
			}

			printf(" %02X:%02X:%02X:%02X:%02X:%02X",
				   na_cur->namac.addr[0],
				   na_cur->namac.addr[1],
				   na_cur->namac.addr[2],
				   na_cur->namac.addr[3],
				   na_cur->namac.addr[4],
				   na_cur->namac.addr[5]);

			printf("  %3d", na_cur->channel);
			printf(" %3d", na_cur->power);
			printf(" %6d", na_cur->ack);
			printf("  %4d", na_cur->ackps);
			printf(" %6d", na_cur->cts);
			printf(" %6d", na_cur->rts_r);
			printf(" %6d", na_cur->rts_t);
			printf(" %6d", na_cur->other);

			erase_line(0);
			putchar('\n');
		}
	}

	erase_display(0);
}

static struct oui * oui_lookup(struct oui * const list, char const * oui)
{
    struct oui * ptr = list;

    while (ptr != NULL)
    {
        bool const found = strcasecmp(ptr->id, oui) == 0;

        if (found)
        {
            goto done;
        }
        ptr = ptr->next;
    }

done:
    return ptr;
}

static char *
get_manufacturer(unsigned char mac0, unsigned char mac1, unsigned char mac2)
{
	char oui[OUI_STR_SIZE];
    char * manuf; 
    FILE * fp = NULL;

	snprintf(oui, sizeof oui, "%02X:%02X:%02X", mac0, mac1, mac2);

    if (lopt.manufacturer_list != NULL)
	{
		// Search in the list
        struct oui const * const ptr = oui_lookup(lopt.manufacturer_list, oui);

        if (ptr != NULL)
        {
            manuf = strdup(ptr->manufacturer);
            ALLEGE(manuf != NULL);
        }
        else
        {
            manuf = NULL;
        }

        goto done;
	}
	else
	{
		// If the file exist, then query it each time we need to get a
		// manufacturer.
        fp = open_oui_file();

        if (fp == NULL)
        {
            manuf = NULL;
            goto done;
        }
        char buffer[BUFSIZ];

        while (fgets(buffer, sizeof(buffer), fp) != NULL)
        {
            unsigned char a[2] = { 0 };
            unsigned char b[2] = { 0 };
            unsigned char c[2] = { 0 };

            if (strstr(buffer, "(hex)") == NULL)
            {
                continue;
            }

            if (sscanf(buffer,
                       "%2c-%2c-%2c",
                       (char *) a,
                       (char *) b,
                       (char *) c)
                == 3)
            {
                char temp[OUI_STR_SIZE];

                snprintf(temp,
                         sizeof(temp),
                         "%c%c:%c%c:%c%c",
                         a[0],
                         a[1],
                         b[0],
                         b[1],
                         c[0],
                         c[1]);

                bool const found = strcasecmp(temp, oui) == 0;

                if (found)
                {
                    manuf = get_manufacturer_from_string(buffer);
                    ALLEGE(manuf != NULL);

                    goto done;
                }
            }
        }
	}

    manuf = NULL;

done:
	if (manuf == NULL)
	{
        // Not found.
        manuf = strdup(unknown_manufacturer);
        ALLEGE(manuf != NULL);
    }

    if (fp != NULL)
    {
        fclose(fp);
    }

	return manuf;
}

/* Read at least one full line from the network.
 *
 * Returns the amount of data in the buffer on success, 0 on connection
 * closed, or a negative value on error.
 *
 * If the return value is >0, the buffer contains at least one newline
 * character.  If the return value is <= 0, the contents of the buffer
 * are undefined.
 */
static inline ssize_t
read_line(int sock, char * buffer, size_t pos, size_t size)
{
	ssize_t status = 1;
	if (size < 1 || pos >= size || buffer == NULL || sock < 0)
	{
		return (-1);
	}

	while (strchr_n(buffer, 0x0A, pos) == NULL && status > 0 && pos < size)
	{
		status = recv(sock, buffer + pos, size - pos, 0);
		if (status > 0)
		{
			pos += status;
		}
	}

	if (status <= 0)
	{
		return (status);
	}
	else if (pos == size && strchr_n(buffer, 0x0A, pos) == NULL)
	{
		return (-1);
	}

	return (pos);
}

/* Extract a name:value pair from a null-terminated line of JSON.
 *
 * Returns 1 if the name was found, or 0 otherwise.
 *
 * The string in "value" is null-terminated if the name was found.  If
 * the name was not found, the contents of "value" are undefined.
 */
static int
json_get_value_for_name(const char * buffer, const char * name, char * value)
{
	char * to_find;
	char * cursor;
	size_t to_find_len;
	char * vcursor = value;
	int ret = 0;

	if (buffer == NULL || strlen(buffer) == 0 || name == NULL
		|| strlen(name) == 0
		|| value == NULL)
	{
		return (0);
	}

	to_find_len = strlen(name) + 3;
	to_find = (char *) malloc(to_find_len);
	ALLEGE(to_find != NULL);
	snprintf(to_find, to_find_len, "\"%s\"", name);
	cursor = strstr(buffer, to_find);
	free(to_find);
	if (cursor != NULL)
	{
		cursor += to_find_len - 1;
		while (*cursor != ':' && *cursor != '\0')
		{
			cursor++;
		}
		if (*cursor != '\0')
		{
			cursor++;
			while (isspace((int) (*cursor)) && *cursor != '\0')
			{
				cursor++;
			}
		}
		if ('\0' == *cursor)
		{
			return (0);
		}

		if ('"' == *cursor)
		{
			/* Quoted string */
			cursor++;
			while (*cursor != '"' && *cursor != '\0')
			{
				if ('\\' == *cursor && '"' == *(cursor + 1))
				{
					/* Escaped quote */
					*vcursor = '"';
					cursor++;
				}
				else
				{
					*vcursor = *cursor;
				}
				vcursor++;
				cursor++;
			}
			*vcursor = '\0';
			ret = 1;
		}
		else if (strncmp(cursor, "true", 4) == 0)
		{
			/* Boolean */
			strcpy(value, "true");
			ret = 1;
		}
		else if (strncmp(cursor, "false", 5) == 0)
		{
			/* Boolean */
			strcpy(value, "false");
			ret = 1;
		}
		else if ('{' == *cursor || '[' == *cursor)
		{
			/* Object or array.  Too hard to handle and not needed for
			 * getting coords from GPSD, so pretend we didn't see anything.
			 */
			ret = 0;
		}
		else
		{
			/* Number, supposedly.  Copy as-is. */
			while (*cursor != ',' && *cursor != '}'
				   && !isspace((int) (*cursor)))
			{
				*vcursor = *cursor;
				cursor++;
				vcursor++;
			}
			*vcursor = '\0';
			ret = 1;
		}
	}

	return (ret);
}

static void * gps_tracker_thread(void * arg)
{
	int gpsd_sock;
	char line[1537], buffer[1537], data[1537];
	char * temp;
	struct sockaddr_in gpsd_addr;
	int is_json;
	ssize_t pos;
	int gpsd_tried_connection = 0;
	fd_set read_fd;
	struct timeval timeout;

    static int const success = 0;
    static int const failure = -1;

    int * const return_value = (int *)arg;
    ALLEGE(return_value != NULL); 

	// In case we GPSd goes down or we lose connection or a fix, we keep trying to connect inside the while loop
	while (lopt.do_exit == 0)
	{
		// If our socket connection to GPSD has been attempted and failed wait before trying again - used to prevent locking the CPU on socket retries
		if (gpsd_tried_connection)
		{
			sleep(2);
		}
		gpsd_tried_connection = 1;

		time_t updateTime = time(NULL);

        /* FIXME - Are these memsets necessary? */
		memset(line, 0, sizeof line);
		memset(buffer, 0, sizeof buffer);
		memset(data, 0, sizeof data);

		/* attempt to connect to localhost, port 2947 */
		pos = 0;
		gpsd_sock = socket(AF_INET, SOCK_STREAM, 0);
		if (gpsd_sock < 0) continue;

        memset(&gpsd_addr, 0, sizeof gpsd_addr);
		gpsd_addr.sin_family = AF_INET;
		gpsd_addr.sin_port = htons(2947);
		gpsd_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
		if (connect(
				gpsd_sock, (struct sockaddr *) &gpsd_addr, sizeof(gpsd_addr))
			< 0)
			continue;

		// Check if it's GPSd < 2.92 or the new one
		// 2.92+ immediately sends version information
		// < 2.92 requires to send PVTAD command
		FD_ZERO(&read_fd);
		FD_SET(gpsd_sock, &read_fd); // NOLINT(hicpp-signed-bitwise)
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		is_json = select(gpsd_sock + 1, &read_fd, NULL, NULL, &timeout);

		if (is_json > 0)
		{
			/* Probably JSON.  Read the first line and verify it's a version of the
			* protocol we speak. */
			if ((pos = read_line(gpsd_sock, buffer, 0, sizeof(buffer))) <= 0)
				continue;

			pos = get_line_from_buffer(buffer, (size_t) pos, line);
			is_json = (json_get_value_for_name(line, "class", data)
					   && strncmp(data, "VERSION", 7) == 0);

			if (is_json)
			{
				/* Verify it's a version of the protocol we speak */
				if (json_get_value_for_name(line, "proto_major", data)
					&& data[0] != '3')
				{
					/* It's an unknown version of the protocol.  Bail out. */
					continue;
				}

				// Send ?WATCH={"json":true};
				strcpy(line, "?WATCH={\"json\":true};\n");
				if (send(gpsd_sock, line, strlen(line), 0) != strlen(line)) continue;
			}
		}
		else if (is_json < 0)
		{
			/* An error occurred while we were waiting for data */
			continue;
		}
		/* Else select() returned zero (timeout expired) and we assume we're
		* connected to an old-style gpsd. */

		// Initialisation of all GPS data to 0
		memset(lopt.gps_loc, 0, sizeof(lopt.gps_loc));

		/* Inside loop for reading the GPS coordinates/data */
		while (lopt.do_exit == 0)
		{
			gpsd_tried_connection = 0; // reset socket connection test
			usleep(500000);

			// Reset all GPS data before each read so that if we lose GPS signal
			// or drop to a 2D fix, the loss of data is accurately reflected
			// gps_loc data structure:
			// 0 = lat, 1 = lon, 2 = speed, 3 = heading, 4 = alt, 5 = lat error, 6 = lon error, 7 = vertical error

			// Check if we need to reset/invalidate our GPS data if the data has become 'stale' based on a timeout/interval
			if (time(NULL) - updateTime > lopt.gps_valid_interval)
			{
				memset(lopt.gps_loc, 0, sizeof(lopt.gps_loc));
			}

			// Record ALL GPS data from GPSD
            /* FIXME: Why does output_format_wifi_scanner need to be 
             * checked? 
             */
            if (opt.record_data && !opt.output_format_wifi_scanner)
			{
				fputs(line, opt.f_gps);
			}

			/* read position, speed, heading, altitude */
			if (is_json)
			{
				// Format definition: http://catb.org/gpsd/gpsd_json.html

				if ((pos = read_line(
						 gpsd_sock, buffer, (size_t) pos, sizeof(buffer)))
					<= 0)
					break;
				pos = get_line_from_buffer(buffer, (size_t) pos, line);

				// See if we got a TPV report - aka actual GPS data if not send default 0 values
				if (!json_get_value_for_name(line, "class", data)
					|| strncmp(data, "TPV", 3) != 0)
				{
					/* Not a TPV report.  Get another line. */

					continue;
				}

				/* See what sort of GPS fix we got.  Possibilities are:
				* 0: No data
				* 1: No fix
				* 2: Lat/Lon, but no alt
				* 3: Lat/Lon/Alt
				* Either 2 or 3 may also have speed and heading data.
				*/
				if (!json_get_value_for_name(line, "mode", data)
					|| (strtol(data, NULL, 10)) < 2)
				{
					/* No GPS fix, so there are no coordinates to extract. */
					continue;
				}

				/* Extract the available data from the TPV report.  If we're
				* in mode 2, latitude and longitude are mandatory, altitude
				* is set to 0, and speed and heading are optional.
				* In mode 3, latitude, longitude, and altitude are mandatory,
				* while speed and heading are optional.
				* If we can't get a mandatory value, the line is discarded
				* as fragmentary or malformed.  If we can't get an optional
				* value, we default it to 0.
				*/

				// GPS Time
				if (json_get_value_for_name(line, "time", data))
				{
					if (!(strptime(data, "%Y-%m-%dT%H:%M:%S", &lopt.gps_time)
						  == NULL))
					{
						updateTime = time(NULL);
					}
				}

				// Latitude
				if (json_get_value_for_name(line, "lat", data))
				{
					lopt.gps_loc[0] = strtof(data, NULL);
					if (errno == EINVAL || errno == ERANGE)
					{
						lopt.gps_loc[0] = 0;
					}
				}

				// Longitude
				if (json_get_value_for_name(line, "lon", data))
				{
					lopt.gps_loc[1] = strtof(data, NULL);
					if (errno == EINVAL || errno == ERANGE)
					{
						lopt.gps_loc[1] = 0;
					}
				}

				// Longitude Error
				if (json_get_value_for_name(line, "epx", data))
				{
					lopt.gps_loc[6] = strtof(data, NULL);
					if (errno == EINVAL || errno == ERANGE)
					{
						lopt.gps_loc[6] = 0;
					}
				}

				// Latitude Error
				if (json_get_value_for_name(line, "epy", data))
				{
					lopt.gps_loc[5] = strtof(data, NULL);
					if (errno == EINVAL || errno == ERANGE)
					{
						lopt.gps_loc[5] = 0;
					}
				}

				// Vertical Error
				if (json_get_value_for_name(line, "epv", data))
				{
					lopt.gps_loc[7] = strtof(data, NULL);
					if (errno == EINVAL || errno == ERANGE)
					{
						lopt.gps_loc[7] = 0;
					}
				}

				// Altitude
				if (json_get_value_for_name(line, "alt", data))
				{
					lopt.gps_loc[4] = strtof(data, NULL);
					if (errno == EINVAL || errno == ERANGE)
					{
						lopt.gps_loc[4] = 0;
					}
				}

				// Speed
				if (json_get_value_for_name(line, "speed", data))
				{
					lopt.gps_loc[2] = strtof(data, NULL);
					if (errno == EINVAL || errno == ERANGE)
					{
						lopt.gps_loc[2] = 0;
					}
				}

				// Heading
				if (json_get_value_for_name(line, "track", data))
				{
					lopt.gps_loc[3] = strtof(data, NULL);
					if (errno == EINVAL || errno == ERANGE)
					{
						lopt.gps_loc[3] = 0;
					}
				}
			}
			else
			{
				// Else read a NON JSON format
				snprintf(line, sizeof(line) - 1, "PVTAD\r\n");
				if (send(gpsd_sock, line, 7, 0) != 7)
				{
                    *return_value = failure;
                    goto done;
				}

				memset(line, 0, sizeof(line));
				if (recv(gpsd_sock, line, sizeof(line) - 1, 0) <= 0)
				{
                    *return_value = failure;
                    goto done;
                }

				if (memcmp(line, "GPSD,P=", 7) != 0) continue;

				/* make sure the coordinates are present */

				if (line[7] == '?') continue;

				int ret;
				updateTime = time(NULL);
				ret = sscanf(line + 7,
							 "%f %f",
							 &lopt.gps_loc[0],
							 &lopt.gps_loc[1]); /* lat lon */
				if (ret == EOF) fprintf(stderr, "Failed to parse lat lon.\n");

				if ((temp = strstr(line, "V=")) == NULL) continue;
				ret = sscanf(temp + 2, "%f", &lopt.gps_loc[2]); /* speed */
				if (ret == EOF) fprintf(stderr, "Failed to parse speed.\n");

				if ((temp = strstr(line, "T=")) == NULL) continue;
				ret = sscanf(temp + 2, "%f", &lopt.gps_loc[3]); /* heading */
				if (ret == EOF) fprintf(stderr, "Failed to parse heading.\n");

				if ((temp = strstr(line, "A=")) == NULL) continue;
				ret = sscanf(temp + 2, "%f", &lopt.gps_loc[4]); /* altitude */
				if (ret == EOF) fprintf(stderr, "Failed to parse altitude.\n");
			}

			lopt.save_gps = 1;
		}

		// If we are still wanting to read GPS but encountered an error - reset data and try again
		if (lopt.do_exit == 0)
		{
			memset(lopt.gps_loc, 0, sizeof(lopt.gps_loc));
			sleep(1);
		}
	}

    *return_value = success;

done:
    return return_value; 
}

static int
wait_proc(pid_t in, pid_t * out)
{
    int stat = 0;
    pid_t pid;

    do
    {
        pid = waitpid(in, &stat, WNOHANG);
    }
    while (pid < 0 && errno == EINTR);

    if (out != NULL)
    {
        *out = pid;
    }

    int status = -1;
    if (WIFEXITED(stat))
    {
        status = WEXITSTATUS(stat);
    }
    else if (WIFSIGNALED(stat))
    {
        status = WTERMSIG(stat);
    }

    return status;
}

static void
sigchld_handler(int signum)
{
    /* Reap zombie processes. */
    pid_t pid;
    int const status = wait_proc(-1, &pid);
    (void)status;
}

static void process_hopper_process_data(
    struct local_options * const options,
    struct hopper_data_st const * const hopper_data)
{
    if (hopper_data->card < 0 || hopper_data->card >= ArrayCount(options->frequency))
    {
        // invalid received data
        fprintf(stderr,
                "Invalid data received for read(opt.cd_pipe[0]), got %d\n",
                hopper_data->card);
        goto done;
    }

    if (options->freqoption != 0)
    {
        options->frequency[hopper_data->card] = hopper_data->u.frequency;
    }
    else
    {
        options->channel[hopper_data->card] = hopper_data->u.channel;
    }

done:
    return;
}

static void update_window_size(struct winsize * const ws)
{
    if (ioctl(0, TIOCGWINSZ, ws) < 0)
    {
        static unsigned short int const default_windows_rows = 25;
        static unsigned short int const default_windows_cols = 80;

        ws->ws_row = default_windows_rows;
        ws->ws_col = default_windows_cols;
    }
}

static void signal_event_shutdown(struct local_options * const options)
{
    if (options->signal_event_pipe[0] != -1)
    {
        int const fd = lopt.signal_event_pipe[0];

        lopt.signal_event_pipe[0] = -1;
        close(fd);
    }

    if (options->signal_event_pipe[1] != -1)
    {
        int const fd = lopt.signal_event_pipe[1];

        options->signal_event_pipe[1] = -1;
        close(fd);
    }
}

static void handle_window_changed_event(struct local_options const * const options)
{
    if (!opt.output_format_wifi_scanner)
    {
        erase_display(0);
        fflush(stdout);
    }
}

static void handle_terminate_event(struct local_options * const options)
{
    show_cursor();
    reset_term();
    fprintf(stdout, "Quitting...\n");
    fflush(stdout); 

    lopt.do_exit = 1;
}

typedef enum
{
    signal_event_window_changed,
    signal_event_terminate
} signal_event_t;

static void send_event(int const fd, int const event)
{
    if (fd != -1)
    {
        IGNORE_LTZ(write(fd, &event, sizeof event));
    }
}

static void send_window_changed_event(struct local_options const * const options)
{
    send_event(options->signal_event_pipe[1], signal_event_window_changed);
}

static void send_terminate_event(struct local_options const * const options)
{
    send_event(options->signal_event_pipe[1], signal_event_terminate);
}

static void sighandler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM)
	{
        send_terminate_event(&lopt);
	}
    else if (signum == SIGWINCH)
    {
        send_window_changed_event(&lopt);
    }
    else if (signum == SIGSEGV)
	{
		fprintf(stderr,
				"Caught signal 11 (SIGSEGV). Please"
				" contact the author!\n\n");
		show_cursor();
		fflush(stdout);
		exit(1);
	}
}

static int send_probe_request(struct wif * wi)
{
	REQUIRE(wi != NULL);

	int len;
	uint8_t p[4096], r_smac[6];

	memcpy(p, PROBE_REQ, 24);

	len = 24;

	p[24] = 0x00; // ESSID Tag Number
	p[25] = 0x00; // ESSID Tag Length

	len += 2;

	memcpy(p + len, RATES, 16);

	len += 16;

	r_smac[0] = 0x00;
	r_smac[1] = rand_u8();
	r_smac[2] = rand_u8();
	r_smac[3] = rand_u8();
	r_smac[4] = rand_u8();
	r_smac[5] = rand_u8();

	memcpy(p + 10, r_smac, 6);

	if (wi_write(wi, NULL, LINKTYPE_IEEE802_11, p, len, NULL) == -1)
	{
		switch (errno)
		{
			case EAGAIN:
			case ENOBUFS:
				usleep(10000);
				return (0); /* XXX not sure I like this... -sorbo */
			default:
				break;
		}

		perror("wi_write()");
		return -1;
	}

	return 0;
}

static int send_probe_requests(struct wif * wi[], int cards)
{
	REQUIRE(wi != NULL);
	REQUIRE(cards > 0);

	for (size_t i = 0; i < cards; i++)
	{
		send_probe_request(wi[i]);
	}

	return (0);
}

static int get_channel_count(
	int const * const channels, 
	int count_valid_channels_only)
{
	int total_channel_count = 0; 
	int valid_channel_count = 0;

	while (channels[total_channel_count] != 0)
	{
		total_channel_count++;
		if (channels[total_channel_count] != -1)
		{
			valid_channel_count++;
		}
	}

	int const channel_count = 
		count_valid_channels_only 
			? valid_channel_count 
			: total_channel_count;

	return channel_count;
}

static int getfreqcount(int valid)
{
	int i = 0, freq_count = 0;

	while (lopt.own_frequencies[i])
	{
		i++;
		if (lopt.own_frequencies[i] != -1) freq_count++;
	}

	if (valid) return (freq_count);
	return (i);
}

static void
channel_hopper(struct wif * wi[], int if_num, int chan_count, pid_t parent)
{
	int ch, ch_idx = 0, card = 0, chi = 0, cai = 0, j = 0, k = 0, first = 1,
			again;
	int dropped = 0;

    /* Continue running as long as the parent is running. */
    while (0 == kill(parent, 0))
	{
		for (j = 0; j < if_num; j++)
		{
			again = 1;

			ch_idx = chi % chan_count;

			card = cai % if_num;

			++chi;
			++cai;

			if (lopt.chswitch == 2 && !first)
			{
				j = if_num - 1;
				card = if_num - 1;

				if (get_channel_count(lopt.channels, 1) > if_num)
				{
					while (again)
					{
						again = 0;
						for (k = 0; k < (if_num - 1); k++)
						{
							if (lopt.channels[ch_idx] == lopt.channel[k])
							{
								again = 1;
								ch_idx = chi % chan_count;
								chi++;
							}
						}
					}
				}
			}

			if (lopt.channels[ch_idx] == -1)
			{
				j--;
				cai--;
				dropped++;
				if (dropped >= chan_count)
				{
					ch = wi_get_channel(wi[card]);
					lopt.channel[card] = ch;

                    struct hopper_data_st const hopper_data =
                    {
                        .card = card,
                        .u.channel = ch
                    };

                    IGNORE_LTZ(write(lopt.hopper_process_pipe[1], &hopper_data, sizeof hopper_data));

					usleep(1000);
				}
				continue;
			}

			dropped = 0;

			ch = lopt.channels[ch_idx];

#ifdef CONFIG_LIBNL
			if (wi_set_ht_channel(wi[card], ch, lopt.htval) == 0)
#else
			if (wi_set_channel(wi[card], ch) == 0)
#endif
			{
                lopt.channel[card] = ch;

                struct hopper_data_st const hopper_data =
                {
                    .card = card,
                    .u.channel = ch
                }; 

                IGNORE_LTZ(write(lopt.hopper_process_pipe[1], &hopper_data, sizeof hopper_data)); 

                if (lopt.active_scan_sim > 0)
                    send_probe_request(wi[card]); 

				usleep(1000);
			}
			else
			{
				lopt.channels[ch_idx] = -1; /* remove invalid channel */
				j--;
				cai--;
				continue;
			}
		}

		if (lopt.chswitch == 0)
		{
			chi = chi - (if_num - 1);
		}

		if (first)
		{
			first = 0;
		}

		usleep((useconds_t)(lopt.hopfreq * 1000));
	}

	exit(0);
}

static void
frequency_hopper(struct wif * wi[], int if_num, int chan_count, pid_t parent)
{
	int ch, ch_idx = 0, card = 0, chi = 0, cai = 0, j = 0, k = 0, first = 1,
			again;
	int dropped = 0;

    /* Continue running as long as the parent is running. */
	while (0 == kill(parent, 0))
	{
		for (j = 0; j < if_num; j++)
		{
			again = 1;

			ch_idx = chi % chan_count;

			card = cai % if_num;

			++chi;
			++cai;

			if (lopt.chswitch == 2 && !first)
			{
				j = if_num - 1;
				card = if_num - 1;

				if (getfreqcount(1) > if_num)
				{
					while (again)
					{
						again = 0;
						for (k = 0; k < (if_num - 1); k++)
						{
							if (lopt.own_frequencies[ch_idx]
								== lopt.frequency[k])
							{
								again = 1;
								ch_idx = chi % chan_count;
								chi++;
							}
						}
					}
				}
			}

			if (lopt.own_frequencies[ch_idx] == -1)
			{
				j--;
				cai--;
				dropped++;
				if (dropped >= chan_count)
				{
					ch = wi_get_freq(wi[card]);
					lopt.frequency[card] = ch;

                    struct hopper_data_st const hopper_data =
                    {
                        .card = card,
                        .u.frequency = ch
                    };

                    IGNORE_LTZ(write(lopt.hopper_process_pipe[1], &hopper_data, sizeof hopper_data)); 

					usleep(1000);
				}
				continue;
			}

			dropped = 0;

			ch = lopt.own_frequencies[ch_idx];

			if (wi_set_freq(wi[card], ch) == 0)
			{
				lopt.frequency[card] = ch;

                struct hopper_data_st const hopper_data =
                {
                    .card = card,
                    .u.frequency = ch
                };

                IGNORE_LTZ(write(lopt.hopper_process_pipe[1], &hopper_data, sizeof hopper_data));

				usleep(1000);
			}
			else
			{
				lopt.own_frequencies[ch_idx] = -1; /* remove invalid channel */
				j--;
				cai--;
				continue;
			}
		}

		if (lopt.chswitch == 0)
		{
			chi = chi - (if_num - 1);
		}

		if (first)
		{
			first = 0;
		}

		usleep((useconds_t)(lopt.hopfreq * 1000));
	}

	exit(0);
}

static inline int invalid_channel(int chan)
{
	int i = 0;

	do
	{
		if (chan == abg_chans[i] && chan != 0) return (0);
	} while (abg_chans[++i]);
	return (1);
}

static inline bool invalid_frequency(
    struct detected_frequencies_st const * const detected_frequencies,
    int const freq)
{
    bool is_invalid;

    for (size_t i = 0; i < detected_frequencies->count; i++)
    {
        if (freq == detected_frequencies->frequencies[i])
        {
            is_invalid = false;
            goto done;
        }
    }

    is_invalid = true; 

done:
    return is_invalid;
}

/* parse a string, for example "1,2,3-7,11" */

static int getchannels(const char * optarg)
{
	unsigned int i = 0, chan_cur = 0, chan_first = 0, chan_last = 0,
				 chan_max = 128, chan_remain = 0;
	char *optchan = NULL, *optc;
	char * token = NULL;
	int * tmp_channels;

	// got a NULL pointer?
	if (optarg == NULL) return (-1);

	chan_remain = chan_max;

	// create a writable string
	optc = optchan = strdup(optarg);
	ALLEGE(optc != NULL);

    tmp_channels = calloc(chan_max + 1, sizeof(int));
	ALLEGE(tmp_channels != NULL);

	// split string in tokens, separated by ','
	while ((token = strsep(&optchan, ",")) != NULL)
	{
		// range defined?
		if (strchr(token, '-') != NULL)
		{
			// only 1 '-' ?
			if (strchr(token, '-') == strrchr(token, '-'))
			{
				// are there any illegal characters?
				for (i = 0; i < strlen(token); i++)
				{
					if (((token[i] < '0') || (token[i] > '9'))
						&& (token[i] != '-'))
					{
						free(tmp_channels);
						free(optc);
						return (-1);
					}
				}

				if (sscanf(token, "%u-%u", &chan_first, &chan_last) != EOF)
				{
					if (chan_first > chan_last)
					{
						free(tmp_channels);
						free(optc);
						return (-1);
					}
					for (i = chan_first; i <= chan_last; i++)
					{
						if ((!invalid_channel(i)) && (chan_remain > 0))
						{
							tmp_channels[chan_max - chan_remain] = i;
							chan_remain--;
						}
					}
				}
				else
				{
					free(tmp_channels);
					free(optc);
					return (-1);
				}
			}
			else
			{
				free(tmp_channels);
				free(optc);
				return (-1);
			}
		}
		else
		{
			// are there any illegal characters?
			for (i = 0; i < strlen(token); i++)
			{
				if ((token[i] < '0') || (token[i] > '9'))
				{
					free(tmp_channels);
					free(optc);
					return (-1);
				}
			}

			if (sscanf(token, "%u", &chan_cur) != EOF)
			{
				if ((!invalid_channel(chan_cur)) && (chan_remain > 0))
				{
					tmp_channels[chan_max - chan_remain] = chan_cur;
					chan_remain--;
				}
			}
			else
			{
				free(tmp_channels);
				free(optc);
				return (-1);
			}
		}
	}

	lopt.own_channels
		= (int *) malloc(sizeof(int) * (chan_max - chan_remain + 1));
	ALLEGE(lopt.own_channels != NULL);

	if (chan_max > 0 && chan_max >= chan_remain) //-V560
	{
		for (i = 0; i < (chan_max - chan_remain); i++) //-V658
		{
			lopt.own_channels[i] = tmp_channels[i];
		}
	}

	lopt.own_channels[i] = 0;

	free(tmp_channels);
	free(optc);
	if (i == 1) return (lopt.own_channels[0]);
	if (i == 0) return (-1);
	return (0);
}

/* parse a string, for example "1,2,3-7,11" */

static int getfrequencies(
    struct detected_frequencies_st * const detected_frequencies, 
    const char * optarg)
{
	unsigned int i = 0, freq_cur = 0, freq_first = 0, freq_last = 0,
				 freq_max = 10000, freq_remain = 0;
	char *optfreq = NULL, *optc;
	char * token = NULL;
	int * tmp_frequencies;

	// got a NULL pointer?
	if (optarg == NULL) return -1;

	freq_remain = freq_max;

	// create a writable string
	optc = optfreq = strdup(optarg);
	ALLEGE(optc != NULL);

    tmp_frequencies = calloc(freq_max + 1, sizeof(int));
	ALLEGE(tmp_frequencies != NULL);

	// split string in tokens, separated by ','
	while ((token = strsep(&optfreq, ",")) != NULL)
	{
		// range defined?
		if (strchr(token, '-') != NULL)
		{
			// only 1 '-' ?
			if (strchr(token, '-') == strrchr(token, '-'))
			{
				// are there any illegal characters?
				for (i = 0; i < strlen(token); i++)
				{
					if ((token[i] < '0' || token[i] > '9') && (token[i] != '-'))
					{
						free(tmp_frequencies);
						free(optc);
						return (-1);
					}
				}

				if (sscanf(token, "%u-%u", &freq_first, &freq_last) != EOF)
				{
					if (freq_first > freq_last)
					{
						free(tmp_frequencies);
						free(optc);
						return (-1);
					}
					for (i = freq_first; i <= freq_last; i++)
					{
                        if ((!invalid_frequency(detected_frequencies, i)) && (freq_remain > 0))
						{
							tmp_frequencies[freq_max - freq_remain] = i;
							freq_remain--;
						}
					}
				}
				else
				{
					free(tmp_frequencies);
					free(optc);
					return (-1);
				}
			}
			else
			{
				free(tmp_frequencies);
				free(optc);
				return (-1);
			}
		}
		else
		{
			// are there any illegal characters?
			for (i = 0; i < strlen(token); i++)
			{
				if ((token[i] < '0') || (token[i] > '9'))
				{
					free(tmp_frequencies);
					free(optc);
					return (-1);
				}
			}

			if (sscanf(token, "%u", &freq_cur) != EOF)
			{
                if ((!invalid_frequency(detected_frequencies, freq_cur)) && (freq_remain > 0))
				{
					tmp_frequencies[freq_max - freq_remain] = freq_cur;
					freq_remain--;
				}

				/* special case "-C 0" means: scan all available frequencies */
				if (freq_cur == 0)
				{
					freq_first = 1;
					freq_last = 9999;
					for (i = freq_first; i <= freq_last; i++)
					{
                        if (!invalid_frequency(detected_frequencies, i)
                            && freq_remain > 0)
						{
							tmp_frequencies[freq_max - freq_remain] = i;
							freq_remain--;
						}
					}
				}
			}
			else
			{
				free(tmp_frequencies);
				free(optc);
				return (-1);
			}
		}
	}

	lopt.own_frequencies
		= (int *) malloc(sizeof(int) * (freq_max - freq_remain + 1));
	ALLEGE(lopt.own_frequencies != NULL);

	if (freq_max > 0 && freq_max >= freq_remain) //-V560
	{
		for (i = 0; i < (freq_max - freq_remain); i++) //-V658
		{
			lopt.own_frequencies[i] = tmp_frequencies[i];
		}
	}

	lopt.own_frequencies[i] = 0;

	free(tmp_frequencies);
	free(optc);
	if (i == 1) return (lopt.own_frequencies[0]); // exactly 1 frequency given
	if (i == 0) return (-1); // error occurred
	return (0); // frequency hopping
}

static int setup_card(char * iface, struct wif ** wis)
{
	REQUIRE(iface != NULL);
	REQUIRE(wis != NULL);

	struct wif * wi;

	wi = wi_open(iface);
	if (!wi) return (-1);
	*wis = wi;

	return (0);
}

static bool name_already_specified(
	char const * const interface_name, 
	char * * const iface, 
	size_t if_count)
{
	bool already_specified;

	for (size_t i = 0; i < if_count; i++)
	{
		if (strcmp(iface[i], interface_name) == 0)
		{
			already_specified = true;
			goto done;
		}
	}

	already_specified = false;

done:
	return already_specified;
}

static int init_cards(
	const char * cardstr, 
	char * * const iface, 
	struct wif * * wi)
{
	char * buffer;
	char * buf = NULL;
	int if_count = 0;
	char * interface_name;

	// Check card string is valid
	if (cardstr == NULL || cardstr[0] == '0')
	{
		if_count = -1;
		goto done;
	}

	buf = buffer = strdup(cardstr);
	if (buf == NULL)
	{
		if_count = -1;
		goto done;
	}

	while (((interface_name = strsep(&buffer, ",")) != NULL)
		   && (if_count < MAX_CARDS))
	{
		/* Ignore repeated interface names. */
		if (name_already_specified(interface_name, iface, if_count))
		{
			continue;
		}

		if (setup_card(interface_name, &wi[if_count]) != 0)
		{
			if_count = -1;
			goto done;
		}

		iface[if_count] = interface_name;
		if_count++;
	}

done:
	free(buf);

	return if_count;
}

static int set_encryption_filter(const char * input)
{
	if (input == NULL) return (1);

	if (strlen(input) < 3) return (1);

	if (strcasecmp(input, "opn") == 0) lopt.f_encrypt |= STD_OPN;

	if (strcasecmp(input, "wep") == 0) lopt.f_encrypt |= STD_WEP;

	if (strcasecmp(input, "wpa") == 0)
	{
		lopt.f_encrypt |= STD_WPA;
		lopt.f_encrypt |= STD_WPA2;
	}

	if (strcasecmp(input, "wpa1") == 0) lopt.f_encrypt |= STD_WPA;

	if (strcasecmp(input, "wpa2") == 0) lopt.f_encrypt |= STD_WPA2;

	return (0);
}

static struct wif * reopen_card(struct wif * const old)
{
    struct wif * new_wi;
	char ifnam[MAX_IFACE_NAME];

    /* The interface name needs to be saved because closing the 
     * card frees all resources associated with the wi. 
     */
    strlcpy(ifnam, wi_get_ifname(old), sizeof ifnam);

    wi_close(old);
    new_wi = wi_open(ifnam);

    if (new_wi == NULL)
    {
        printf("Can't reopen %s\n", ifnam);
    }

    return new_wi;
}

static bool reopen_cards(
    struct local_options const * const options,
    struct wif * * const wi)
{
    bool success;

    for (size_t i = 0; i < options->num_cards; i++)
    {
        wi[i] = reopen_card(wi[i]);
        if (wi[i] == NULL)
        {
            success = false;
            goto done;
        }
    }

    success = true;

done:
    return success;
}

static int check_monitor(struct wif * wi[], int * fd_raw, int * fdh, int cards)
{
	for (size_t i = 0; i < cards; i++)
	{
		int const monitor = wi_get_monitor(wi[i]);
		if (monitor != 0)
		{
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ %s reset to monitor mode",
					 wi_get_ifname(wi[i]));
			// reopen in monitor mode
            wi[i] = reopen_card(wi[i]);
			if (wi[i] == NULL)
			{
				exit(1);
			}

			fd_raw[i] = wi_fd(wi[i]);
			if (fd_raw[i] > *fdh) *fdh = fd_raw[i];
		}
	}

	return 0;
}

static int check_channel(struct wif * wi[], int cards)
{
	for (size_t i = 0; i < cards; i++)
	{
		int const chan = wi_get_channel(wi[i]);

		if (opt.ignore_negative_one == 1 && chan == -1) return (0);
		if (lopt.channel[i] != chan)
		{
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ fixed channel %s: %d ",
					 wi_get_ifname(wi[i]),
					 chan);
#ifdef CONFIG_LIBNL
			wi_set_ht_channel(wi[i], lopt.channel[i], lopt.htval);
#else
			wi_set_channel(wi[i], lopt.channel[i]);
#endif
		}
	}
	return 0;
}

static int check_frequency(struct wif * wi[], int cards)
{
	for (size_t i = 0; i < cards; i++)
	{
        int const freq = wi_get_freq(wi[i]);

		if (freq < 0) continue;
		if (lopt.frequency[i] != freq)
		{
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ fixed frequency %s: %d ",
					 wi_get_ifname(wi[i]),
					 freq);
			wi_set_freq(wi[i], lopt.frequency[i]);
		}
	}
	return 0;
}

static void detect_frequency_range(
    struct wif * wi, 
    struct detected_frequencies_st * const detected_frequencies,
    size_t const start_freq, 
    size_t const end_freq)
{
    for (int freq = start_freq; 
          detected_frequencies->count < detected_frequencies->table_size && freq <= end_freq; 
          freq += 5)
    {
        if (wi_set_freq(wi, freq) == 0)
        {
            detected_frequencies->frequencies[detected_frequencies->count] = freq;
            detected_frequencies->count++;
        }

        int const channel_13_freq = 2482;

        if (freq == channel_13_freq)
        {
            int const channel_14_freq = 2484;
            // special case for chan 14, as its 12MHz away from 13, not 5MHz
            if (wi_set_freq(wi, channel_14_freq) == 0)
            {
                detected_frequencies->frequencies[detected_frequencies->count] = channel_14_freq;
                detected_frequencies->count++;
            }
        }
    }
}

static void detected_frequencies_initialise(
    struct detected_frequencies_st * const detected_frequencies,
    size_t const max_frequencies)
{
    detected_frequencies->count = 0;
    detected_frequencies->table_size = max_frequencies;
    // field for frequencies supported
    detected_frequencies->frequencies =
        calloc(detected_frequencies->table_size, sizeof(int));

    ALLEGE(detected_frequencies->frequencies != NULL);
}

static void detected_frequencies_cleanup(
    struct detected_frequencies_st * const detected_frequencies)
{
    free(detected_frequencies->frequencies);
    detected_frequencies->frequencies = NULL;
}


static void detect_frequencies(
    struct wif * wi, 
    struct detected_frequencies_st * const detected_frequencies)
{
	REQUIRE(wi != NULL);

    size_t const max_freq_num = 2048; // should be enough to keep all available channels

	printf("Checking available frequencies; this could take few seconds.\n");

    detected_frequencies_initialise(detected_frequencies, max_freq_num);

    int start_freq = 2192;
    int end_freq = 2732;
    detect_frequency_range(wi, detected_frequencies, start_freq, end_freq);

    // again for 5GHz channels
    start_freq = 4800;
    end_freq = 6000;
    detect_frequency_range(wi, detected_frequencies, start_freq, end_freq);

    printf("Done. Found %zu frequencies\n", detected_frequencies->count);
}

static int array_contains(const int * array, int length, int value)
{
	REQUIRE(array != NULL);
	REQUIRE(length >= 0 && length < INT_MAX);

	int i;
	for (i = 0; i < length; i++)
		if (array[i] == value) return (1);

	return (0);
}

static int rearrange_frequencies(void)
{
	int * freqs;
	int count, left, pos;
	int width, last_used = 0;
	int cur_freq, round_done;

	width = DEFAULT_CWIDTH;

	count = getfreqcount(0);
	left = count;
	pos = 0;

	freqs = calloc(count + 1, sizeof *freqs);
	ALLEGE(freqs != NULL);
	round_done = 0;

	while (left > 0)
	{
		cur_freq = lopt.own_frequencies[pos % count];

		if (cur_freq == last_used) round_done = 1;

		if (((count - left) > 0) && !round_done
			&& (ABS(last_used - cur_freq) < width))
		{
			pos++;
			continue;
		}

		if (!array_contains(freqs, count, cur_freq))
		{
			freqs[count - left] = cur_freq;
			last_used = cur_freq;
			left--;
			round_done = 0;
		}

		pos++;
	}

	memcpy(lopt.own_frequencies, freqs, count * sizeof(int));
	free(freqs);

	return (0);
}

static int start_monitor_process(
    struct local_options * const options, 
    struct wif * * const wi)
{
    int result; /* -1: error, 0: child process, 1: parent_process */
    int const pipe_result = pipe(options->hopper_process_pipe);

    IGNORE_NZ(pipe_result);

    result = fork();

    if (result == -1)
    {
        exit(EXIT_FAILURE);
    }

    if (result == 0)
    {
        /* This is the child process. */

        /* Close the read end of the communications pipe as the child 
         * only writes data for the parent to read. 
         */
        close(options->hopper_process_pipe[0]);

        /* reopen cards. This way parent & child don't share
        * resources for
        * accessing the card (e.g. file descriptors) which may cause
        * problems.  -sorbo
        */

        if (!reopen_cards(options, wi))
        {
            exit(EXIT_FAILURE);
        }

        /* Drop privileges */
        if (setuid(getuid()) == -1)
        {
            perror("setuid");
        }
    }
    else
    {
        /* This is the parent process. */
        /* Close the write end of the communications pipe as the parent 
         * only reads data written by the child. 
         */
        close(options->hopper_process_pipe[1]);
    }

    return result;
}

static void start_frequency_hopper_process(
    struct local_options * const options,
    struct wif * * const wi,
    int const frequency_count)
{
    pid_t const main_pid = getpid();
    int const result = start_monitor_process(options, wi);

    if (result == 0)
    {
        frequency_hopper(wi, options->num_cards, frequency_count, main_pid);
        exit(EXIT_FAILURE);
    }
}

static void start_channel_hopper_process(
    struct local_options * const options,
    struct wif * * const wi,
    int const channel_count)
{
    pid_t const main_pid = getpid();
    int const result = start_monitor_process(options, wi);

    if (result == 0)
    {
        channel_hopper(wi, options->num_cards, channel_count, main_pid);
        exit(EXIT_FAILURE);
    }
}

static bool pipe_has_data_ready(int const fd)
{
    bool have_data_ready;
    fd_set rfds;

    if (fd == -1)
    {
        have_data_ready = false;
        goto done;
    }

    int pipe_ready;
    do
    {
        struct timeval tv =
        {
            .tv_sec = 0,
            .tv_usec = 0
        };
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds); // NOLINT(hicpp-signed-bitwise)
        pipe_ready = select(fd + 1, &rfds, NULL, NULL, &tv);
    }
    while (pipe_ready < 0 && errno == EINTR);

    if (pipe_ready <= 0 || !FD_ISSET(fd, &rfds))
    {
        have_data_ready = false;
        goto done;
    }

    have_data_ready = true;

done:
    return have_data_ready;
}

static bool pipe_read(int const fd, void * const data, size_t data_size)
{
    bool have_read_data;

    if (!pipe_has_data_ready(fd))
    {
        have_read_data = false;
        goto done;
    }

    int read_result;
    do
    {
        read_result = read(fd, data, data_size);
    }
    while (read_result < 0 && errno == EINTR);

    have_read_data = read_result == data_size;

done:
    return have_read_data;
}

static void check_monitor_process(struct local_options * const options)
{
    struct hopper_data_st hopper_data = { 0 };

    while (pipe_read(options->hopper_process_pipe[0], 
                     &hopper_data, 
                     sizeof hopper_data))
    {
        process_hopper_process_data(options, &hopper_data);
    }
}

static void process_event(
    struct local_options * const options, 
    signal_event_t const event)
{
    switch (event)
    {
        case signal_event_window_changed:
            handle_window_changed_event(options);
            break;
        case signal_event_terminate:
            handle_terminate_event(options);
            break;
        default:
            /* Unknown event. */
            break;
    }
}

static void check_for_signal_events(struct local_options * const options)
{
    int event = 0;

    while (pipe_read(options->signal_event_pipe[0], 
                     &event, 
                     sizeof event))
    {
        process_event(options, event);
    }
}

static void flush_output_files(void)
{
    if (opt.f_cap != NULL)
    {
        fflush(opt.f_cap);
    }

    if (opt.f_ivs != NULL)
    {
        fflush(opt.f_ivs);
    }
}

static void sta_list_free(struct sta_list_head * const sta_list)
{
	while (TAILQ_FIRST(sta_list) != NULL)
	{
		struct ST_info * const st_cur = TAILQ_FIRST(sta_list); 

		TAILQ_REMOVE(sta_list, st_cur, entry);

		free(st_cur->manuf);
		free(st_cur);
	}
}

static void ap_list_free(struct ap_list_head * const ap_list)
{
	while (TAILQ_FIRST(ap_list) != NULL)
	{
		struct AP_info * const ap_cur = TAILQ_FIRST(ap_list);

		TAILQ_REMOVE(ap_list, ap_cur, entry);

		// Clean content of ap_cur list (first element: lopt.ap_1st)
		uniqueiv_wipe(ap_cur->uiv_root);

		packet_list_free(&ap_cur->pkt_list);

		data_wipe(ap_cur->data_root);

		free(ap_cur->manuf);
		free(ap_cur);
	}
}

int main(int argc, char * argv[])
{
#define ONE_HOUR (60 * 60)
#define ONE_MIN (60)

    long time_slept, cycle_time, cycle_time2;
	char * output_format_string;
	int caplen = 0, i, j, fdh, freq_count;
	int fd_raw[MAX_CARDS], arptype[MAX_CARDS];
	int ivs_only, found;
	int freq[2];
	int num_opts = 0;
	int option = 0;
	int option_index = 0;
	int wi_read_failed = 0;
	int n = 0;
    int reset_val = 0;
    int output_format_first_time = 1;
#ifdef HAVE_PCRE
	const char * pcreerror;
	int pcreerroffset;
#endif
    struct pcap_pkthdr pkh;

	time_t tt1, tt2, start_time;

	struct wif * wi[MAX_CARDS];
	struct rx_info ri;
	unsigned char tmpbuf[4096];
	unsigned char buffer[4096];
	unsigned char * h80211;
	char * iface[MAX_CARDS];

	struct timeval tv0;
	struct timeval tv1;
	struct timeval tv2;
	struct timeval tv3;
	struct timeval tv4;
	struct tm * lt;

	/*
	struct sockaddr_in provis_addr;
	*/

	fd_set rfds;

	static const struct option long_options[]
		= {{"ht20", 0, 0, '2'},
		   {"ht40-", 0, 0, '3'},
		   {"ht40+", 0, 0, '5'},
		   {"band", 1, 0, 'b'},
		   {"beacon", 0, 0, 'e'},
		   {"beacons", 0, 0, 'e'},
		   {"cswitch", 1, 0, 's'},
		   {"netmask", 1, 0, 'm'},
		   {"bssid", 1, 0, 'd'},
		   {"essid", 1, 0, 'N'},
		   {"essid-regex", 1, 0, 'R'},
		   {"channel", 1, 0, 'c'},
		   {"gpsd", 0, 0, 'g'},
		   {"ivs", 0, 0, 'i'},
		   {"write", 1, 0, 'w'},
		   {"encrypt", 1, 0, 't'},
		   {"update", 1, 0, 'u'},
		   {"berlin", 1, 0, 'B'},
		   {"help", 0, 0, 'H'},
		   {"nodecloak", 0, 0, 'D'},
		   {"showack", 0, 0, 'A'},
		   {"detect-anomaly", 0, 0, 'E'},
		   {"output-format", 1, 0, 'o'},
           {"sys-name", 1, 0, 'X'},
           {"loc-name", 1, 0, 'y'},
           {"filter-seconds", 1, 0, 'F'},
           {"file-reset-minutes", 1, 0, 'P'},
           {"ignore-negative-one", 0, &opt.ignore_negative_one, 1 },
		   {"manufacturer", 0, 0, 'M'},
		   {"uptime", 0, 0, 'U'},
		   {"write-interval", 1, 0, 'I'},
		   {"wps", 0, 0, 'W'},
		   {"background", 1, 0, 'K'},
		   {"min-packets", 1, 0, 'n'},
		   {"real-time", 0, 0, 'T'},
		   {0, 0, 0, 0}};

	console_utf8_enable();
	ac_crypto_init();

    initialise_print_lock(&lopt);
    initialise_sort_lock(&lopt);

	textstyle(TEXT_RESET); //(TEXT_RESET, TEXT_BLACK, TEXT_WHITE);

	/* initialize a bunch of variables */

	rand_init();
	memset(&opt, 0, sizeof(opt));
	memset(&lopt, 0, sizeof(lopt));

	h80211 = NULL;
	ivs_only = 0;
	lopt.chanoption = 0;
	lopt.freqoption = 0;
	lopt.num_cards = 0;
	fdh = 0;
	time_slept = 0;
	lopt.batt = NULL;
	lopt.chswitch = 0;
	opt.usegpsd = 0;
	lopt.channels = bg_chans;
	lopt.one_beacon = 1;
	lopt.singlechan = 0;
	lopt.singlefreq = 0;
	lopt.dump_prefix = NULL;
	opt.record_data = 0;
	opt.f_cap = NULL;
	opt.f_ivs = NULL;
	opt.f_txt = NULL;
    opt.f_wifi = NULL;
	opt.f_kis = NULL;
	opt.f_kis_xml = NULL;
    opt.f_gps = NULL;
	opt.f_logcsv = NULL;
    lopt.keyout = NULL;
	opt.f_xor = NULL;
	opt.sk_len = 0;
	opt.sk_len2 = 0;
	opt.sk_start = 0;
	opt.prefix = NULL;
	lopt.f_encrypt = 0;
	lopt.asso_client = 0;
	lopt.f_essid = NULL;
	lopt.f_essid_count = 0;
	lopt.active_scan_sim = 0;
	lopt.update_s = 0;
	lopt.decloak = 1;
	lopt.is_berlin = 0;
	lopt.numaps = 0;
	lopt.maxnumaps = 0;
	lopt.berlin = 120;
	lopt.show_ap = 1;
	lopt.show_sta = 1;
	lopt.show_ack = 0;
	lopt.hide_known = 0;
	lopt.maxsize_essid_seen = 5; // Initial value: length of "ESSID"
	lopt.show_manufacturer = 0;
	lopt.show_uptime = 0;
	lopt.hopfreq = DEFAULT_HOPFREQ;
	opt.s_file = NULL;
	lopt.s_iface = NULL;
	lopt.f_cap_in = NULL;
	lopt.detect_anomaly = 0;
	lopt.airodump_start_time = NULL;
    lopt.manufacturer_list = NULL;

    lopt.hopper_process_pipe[0] = -1;
    lopt.hopper_process_pipe[1] = -1; 
    lopt.signal_event_pipe[0] = -1;
    lopt.signal_event_pipe[1] = -1;

	opt.output_format_pcap = 1;
	opt.output_format_csv = 1;
	opt.output_format_kismet_csv = 1;
	opt.output_format_kismet_netxml = 1;
	opt.output_format_log_csv = 1;
    opt.output_format_wifi_scanner = 1;
    lopt.gps_valid_interval
		= 5; // If we dont get a new GPS update in 5 seconds - invalidate it
	lopt.file_write_interval = 5; // Write file every 5 seconds by default
	lopt.maxsize_wps_seen = 6;
	lopt.show_wps = 0;
	lopt.background_mode = -1;
    lopt.sys_name[0] = '\0';
    lopt.loc_name[0] = '\0';
    lopt.filter_seconds = ONE_HOUR;
    lopt.file_reset_seconds = ONE_MIN;
    opt.last_file_reset = 0;
    lopt.do_exit = 0;
	lopt.min_pkts = 2;
	lopt.relative_time = 0;
#ifdef CONFIG_LIBNL
	lopt.htval = CHANNEL_NO_HT;
#endif
#ifdef HAVE_PCRE
	lopt.f_essid_regex = NULL;
#endif

	TAILQ_INIT(&lopt.na_list);
	/* TODO: helper function. Use pointer rather than index. */
	TAILQ_INIT(&lopt.ap_list[0]);
	TAILQ_INIT(&lopt.ap_list[1]); 
	lopt.current_ap_list_index = 0;

	/* TODO: helper function. Use pointer rather than index. */
	TAILQ_INIT(&lopt.sta_list[0]);
	TAILQ_INIT(&lopt.sta_list[1]); 
	lopt.current_sta_list_index = 0; 


	// Default selection.
	resetSelection();

	memset(opt.sharedkey, '\x00', sizeof(opt.sharedkey));
    lopt.message[0] = '\0';
    memset(&lopt.pfh_in, '\x00', sizeof(lopt.pfh_in));

	gettimeofday(&tv0, NULL);

	lt = localtime(&tv0.tv_sec);

    static size_t const keyout_buf_size = 512;
    lopt.keyout = malloc(keyout_buf_size);
	ALLEGE(lopt.keyout != NULL);

	snprintf(lopt.keyout,
             keyout_buf_size,
			 "keyout-%02d%02d-%02d%02d%02d.keys",
			 lt->tm_mon + 1,
			 lt->tm_mday,
			 lt->tm_hour,
			 lt->tm_min,
			 lt->tm_sec);

	for (i = 0; i < MAX_CARDS; i++)
	{
		arptype[i] = 0;
		fd_raw[i] = -1;
		lopt.channel[i] = 0;
	}

    MAC_ADDRESS_CLEAR(&opt.f_bssid);
    memset(opt.f_netmask, '\x00', sizeof opt.f_netmask);
    MAC_ADDRESS_CLEAR(&lopt.wpa_bssid);

	/* check the arguments */

    for (i = 0; long_options[i].name != NULL; i++)
    {
		; /* Do nothing. */
    }
	num_opts = i;

	for (i = 0; i < argc; i++) // go through all arguments
	{
		found = 0;
		if (strlen(argv[i]) >= 3)
		{
			if (argv[i][0] == '-' && argv[i][1] != '-')
			{
				// we got a single dash followed by at least 2 chars
				// lets check that against our long options to find errors
				for (j = 0; j < num_opts; j++)
				{
					if (strcmp(argv[i] + 1, long_options[j].name) == 0)
					{
						// found long option after single dash
						found = 1;
						if (i > 1 && strcmp(argv[i - 1], "-") == 0)
						{
							// separated dashes?
							printf("Notice: You specified \"%s %s\". Did you "
								   "mean \"%s%s\" instead?\n",
								   argv[i - 1],
								   argv[i],
								   argv[i - 1],
								   argv[i]);
						}
						else
						{
							// forgot second dash?
							printf("Notice: You specified \"%s\". Did you mean "
								   "\"-%s\" instead?\n",
								   argv[i],
								   argv[i]);
						}
						break;
					}
				}
				if (found)
				{
					sleep(3);
					break;
				}
			}
		}
	}

	do
	{
		option_index = 0;

		option
			= getopt_long(argc,
						  argv,
                          "b:c:egiw:s:t:u:m:d:N:R:aHDB:Ahf:r:EC:o:x:MUI:WK:n:T:F:P:",
                          long_options,
						  &option_index);

		if (option < 0) break;

		switch (option)
		{
			case 0:

				break;

			case ':':

				printf("\"%s --help\" for help.\n", argv[0]);
				return (EXIT_FAILURE);

			case '?':

				printf("\"%s --help\" for help.\n", argv[0]);
				return (EXIT_FAILURE);

			case 'K':
			{
				char * invalid_str = NULL;
				long int bg_mode = strtol(optarg, &invalid_str, 10);

				if ((invalid_str && *invalid_str != 0)
					|| !(bg_mode == 0 || bg_mode == 1))
				{
					printf("Invalid background mode. Must be '0' or '1'\n");
					exit(EXIT_FAILURE);
				}
				lopt.background_mode = bg_mode;
				break;
			}
			case 'I':

				if (!is_string_number(optarg))
				{
					printf("Error: Write interval is not a number (>0). "
						   "Aborting.\n");
					exit(EXIT_FAILURE);
				}

				lopt.file_write_interval = (int) strtol(optarg, NULL, 10);

				if (lopt.file_write_interval <= 0)
				{
					printf("Error: Write interval must be greater than 0. "
						   "Aborting.\n");
					exit(EXIT_FAILURE);
				}
				break;

			case 'T':
				lopt.relative_time = 1;
				break;

			case 'E':
				lopt.detect_anomaly = 1;
				break;

			case 'e':

				lopt.one_beacon = 0;
				break;

			case 'a':

				lopt.asso_client = 1;
				break;

			case 'A':

				lopt.show_ack = 1;
				break;

			case 'h':

				lopt.hide_known = 1;
				break;

			case 'D':

				lopt.decloak = 0;
				break;

			case 'M':

				lopt.show_manufacturer = 1;
				break;

			case 'U':
				lopt.show_uptime = 1;
				break;

			case 'W':

				lopt.show_wps = 1;
				break;

			case 'c':

				if (lopt.channel[0] > 0 || lopt.chanoption == 1)
				{
					if (lopt.chanoption == 1)
						printf("Notice: Channel range already given\n");
					else
						printf("Notice: Channel already given (%d)\n",
							   lopt.channel[0]);
					break;
				}

				lopt.channel[0] = getchannels(optarg);

				if (lopt.channel[0] < 0)
				{
					airodump_usage();
					return (EXIT_FAILURE);
				}

				lopt.chanoption = 1;

				if (lopt.channel[0] == 0)
				{
					lopt.channels = lopt.own_channels;
				}
                else
                {
                    lopt.channels = bg_chans;
                }
				break;

			case 'C':

				if (lopt.channel[0] > 0 || lopt.chanoption == 1)
				{
					if (lopt.chanoption == 1)
						printf("Notice: Channel range already given\n");
					else
						printf("Notice: Channel already given (%d)\n",
							   lopt.channel[0]);
					break;
				}

				if (lopt.freqoption == 1)
				{
					printf("Notice: Frequency range already given\n");
					break;
				}

				lopt.freqstring = optarg;

				lopt.freqoption = 1;

				break;

			case 'b':

				if (lopt.chanoption == 1)
				{
					printf("Notice: Channel range already given\n");
					break;
				}
				freq[0] = freq[1] = 0;

				for (i = 0; i < (int) strlen(optarg); i++)
				{
					if (optarg[i] == 'a')
						freq[1] = 1;
					else if (optarg[i] == 'b' || optarg[i] == 'g')
						freq[0] = 1;
					else
					{
						printf("Error: invalid band (%c)\n", optarg[i]);
						printf("\"%s --help\" for help.\n", argv[0]);
						exit(EXIT_FAILURE);
					}
				}

                if (freq[1] + freq[0] == 2)
                {
					lopt.channels = abg_chans;
                }
                else if (freq[1] == 1)
                {
                    lopt.channels = a_chans;
                }
                else
                {
                    lopt.channels = bg_chans;
                }

				break;

			case 'i':

				// Reset output format if it's the first time the option is
				// specified
				if (output_format_first_time)
				{
					output_format_first_time = 0;

					opt.output_format_pcap = 0;
					opt.output_format_csv = 0;
					opt.output_format_kismet_csv = 0;
					opt.output_format_kismet_netxml = 0;
					opt.output_format_log_csv = 0;
				}

				if (opt.output_format_pcap)
				{
					airodump_usage();
					fprintf(stderr,
							"Invalid output format: IVS and PCAP "
							"format cannot be used together.\n");
					return (EXIT_FAILURE);
				}

				ivs_only = 1;
				break;

			case 'g':

				opt.usegpsd = 1;
				break;

			case 'w':

				if (lopt.dump_prefix != NULL)
				{
					printf("Notice: dump prefix already given\n");
					break;
				}
				/* Write prefix */
				lopt.dump_prefix = optarg;
				opt.record_data = 1;
				break;

			case 'r':

				if (opt.s_file)
				{
					printf("Packet source already specified.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}
				opt.s_file = optarg;
				break;

			case 's':

				if (strtol(optarg, NULL, 10) > 2 || errno == EINVAL)
				{
					airodump_usage();
					return (EXIT_FAILURE);
				}
				if (lopt.chswitch != 0)
				{
					printf("Notice: switching method already given\n");
					break;
				}
				lopt.chswitch = (int) strtol(optarg, NULL, 10);
				break;

			case 'u':

				lopt.update_s = (int) strtol(optarg, NULL, 10);

				/* If failed to parse or value <= 0, use default, 100ms */
				if (lopt.update_s <= 0) lopt.update_s = REFRESH_RATE;

				break;

			case 'f':

				lopt.hopfreq = (int) strtol(optarg, NULL, 10);

				/* If failed to parse or value <= 0, use default, 100ms */
				if (lopt.hopfreq <= 0) lopt.hopfreq = DEFAULT_HOPFREQ;

				break;

			case 'B':

				lopt.is_berlin = 1;
				lopt.berlin = (int) strtol(optarg, NULL, 10);
				if (lopt.berlin <= 0)
				{
					lopt.berlin = 120;
				}

				break;

			case 'm':

				if (memcmp(opt.f_netmask, NULL_MAC, 6) != 0)
				{
					printf("Notice: netmask already given\n");
					break;
				}
				if (getmac(optarg, 1, opt.f_netmask) != 0)
				{
					printf("Notice: invalid netmask\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}
				break;

			case 'd':

				if (!MAC_ADDRESS_IS_EMPTY(&opt.f_bssid))
				{
					printf("Notice: bssid already given\n");
					break;
				}
				if (getmac(optarg, 1, (uint8_t *)&opt.f_bssid) != 0)
				{
					printf("Notice: invalid bssid\n");
					printf("\"%s --help\" for help.\n", argv[0]);

					return (EXIT_FAILURE);
				}
				break;

			case 'N':

				lopt.f_essid_count++;
				lopt.f_essid = (char **) realloc( //-V701
					lopt.f_essid,
					lopt.f_essid_count * sizeof(char *));
				ALLEGE(lopt.f_essid != NULL);
				lopt.f_essid[lopt.f_essid_count - 1] = optarg;
				break;

			case 'R':

#ifdef HAVE_PCRE
				if (lopt.f_essid_regex != NULL)
				{
					printf("Error: ESSID regular expression already given. "
						   "Aborting\n");
					exit(EXIT_FAILURE);
				}

				lopt.f_essid_regex
					= pcre_compile(optarg, 0, &pcreerror, &pcreerroffset, NULL);

				if (lopt.f_essid_regex == NULL)
				{
					printf("Error: regular expression compilation failed at "
						   "offset %d: %s; aborting\n",
						   pcreerroffset,
						   pcreerror);
					exit(EXIT_FAILURE);
				}
#else
				printf("Error: Airodump-ng wasn't compiled with pcre support; "
					   "aborting\n");
#endif

				break;

			case 't':

				set_encryption_filter(optarg);
				break;

			case 'n':

				lopt.min_pkts = strtoul(optarg, NULL, 10);
				break;

            case 'X':
                strlcpy(lopt.sys_name, optarg, sizeof lopt.sys_name);
                break;
                    
            case 'y':
                strlcpy(lopt.loc_name, optarg, sizeof lopt.loc_name);
                break;
                    
            case 'F':
                lopt.filter_seconds = strtoul(optarg, NULL, 10);
                break;
                   
            case 'P':
                reset_val = strtoul(optarg, NULL, 10);
                lopt.file_reset_seconds = reset_val * ONE_MIN;
                break;
                    
            case 'o':

				// Reset output format if it's the first time the option is
				// specified
				if (output_format_first_time)
				{
					output_format_first_time = 0;

					opt.output_format_pcap = 0;
					opt.output_format_csv = 0;
					opt.output_format_kismet_csv = 0;
					opt.output_format_kismet_netxml = 0;
					opt.output_format_log_csv = 0;
                    opt.output_format_wifi_scanner = 0;
				}

				// Parse the value
				output_format_string = strtok(optarg, ",");
				while (output_format_string != NULL)
				{
					if (strlen(output_format_string) > 0)
					{
						if (strncasecmp(output_format_string, "csv", 3) == 0
							|| strncasecmp(output_format_string, "txt", 3) == 0)
						{
							opt.output_format_csv = 1;
						}
						else if (strncasecmp(output_format_string, "pcap", 4)
									 == 0
								 || strncasecmp(output_format_string, "cap", 3)
										== 0)
						{
							if (ivs_only)
							{
								airodump_usage();
								fprintf(stderr,
										"Invalid output format: IVS "
										"and PCAP format cannot be "
										"used together.\n");
								return (EXIT_FAILURE);
							}
							opt.output_format_pcap = 1;
						}
						else if (strncasecmp(output_format_string, "ivs", 3)
								 == 0)
						{
							if (opt.output_format_pcap)
							{
								airodump_usage();
								fprintf(stderr,
										"Invalid output format: IVS "
										"and PCAP format cannot be "
										"used together.\n");
								return (EXIT_FAILURE);
							}
							ivs_only = 1;
						}
						else if (strncasecmp(output_format_string, "kismet", 6)
								 == 0)
						{
							opt.output_format_kismet_csv = 1;
						}
						else if (strncasecmp(output_format_string, "gps", 3)
								 == 0)
						{
							opt.usegpsd = 1;
						}
						else if (strncasecmp(output_format_string, "netxml", 6)
									 == 0
								 || strncasecmp(
										output_format_string, "newcore", 7)
										== 0
								 || strncasecmp(
										output_format_string, "kismet-nc", 9)
										== 0
								 || strncasecmp(
										output_format_string, "kismet_nc", 9)
										== 0
								 || strncasecmp(output_format_string,
												"kismet-newcore",
												14)
										== 0
								 || strncasecmp(output_format_string,
												"kismet_newcore",
												14)
										== 0)
						{
							opt.output_format_kismet_netxml = 1;
						}
						else if (strncasecmp(output_format_string, "logcsv", 6)
								 == 0)
						{
							opt.output_format_log_csv = 1;
						}
                        else if (strncasecmp(output_format_string, "wifi_scanner", 12) == 0)
                        {
                            opt.output_format_wifi_scanner = 1;
                        }
                        else if (strncasecmp(output_format_string, "default", 7)
								 == 0)
						{
							opt.output_format_pcap = 1;
							opt.output_format_csv = 1;
							opt.output_format_kismet_csv = 1;
							opt.output_format_kismet_netxml = 1;
                            opt.output_format_wifi_scanner = 1;
                        }
						else if (strncasecmp(output_format_string, "none", 4)
								 == 0)
						{
							opt.output_format_pcap = 0;
							opt.output_format_csv = 0;
							opt.output_format_kismet_csv = 0;
							opt.output_format_kismet_netxml = 0;
							opt.output_format_log_csv = 0;
                            opt.output_format_wifi_scanner = 0;
							opt.usegpsd = 0;
							ivs_only = 0;
						}
						else
						{
							// Display an error if it does not match any value
							fprintf(stderr,
									"Invalid output format: <%s>\n",
									output_format_string);
							exit(EXIT_FAILURE);
						}
					}
					output_format_string = strtok(NULL, ",");
				}

				break;

			case 'H':
				airodump_usage();
				return (EXIT_FAILURE);

			case 'x':

				lopt.active_scan_sim = (int) strtol(optarg, NULL, 10);

				if (lopt.active_scan_sim <= 0) lopt.active_scan_sim = 0;
				break;

			case '2':
#ifndef CONFIG_LIBNL
				printf("HT Channel unsupported\n");
				return (EXIT_FAILURE);
#else
				lopt.htval = CHANNEL_HT20;
#endif
				break;
			case '3':
#ifndef CONFIG_LIBNL
				printf("HT Channel unsupported\n");
				return (EXIT_FAILURE);
#else
				lopt.htval = CHANNEL_HT40_MINUS;
#endif
				break;
			case '5':
#ifndef CONFIG_LIBNL
				printf("HT Channel unsupported\n");
				return (EXIT_FAILURE);
#else
				lopt.htval = CHANNEL_HT40_PLUS;
#endif
				break;

			default:
				airodump_usage();
				return (EXIT_FAILURE);
		}
	} while (1);

	if (argc - optind != 1 && opt.s_file == NULL)
	{
		if (argc == 1)
		{
			airodump_usage();
		}
		if (argc - optind == 0)
		{
			printf("No interface specified.\n");
		}
		if (argc > 1)
		{
			printf("\"%s --help\" for help.\n", argv[0]);
		}
		return (EXIT_FAILURE);
	}

	if (argc - optind == 1) lopt.s_iface = argv[argc - 1];

	if (memcmp(opt.f_netmask, NULL_MAC, 6) != 0
		&& MAC_ADDRESS_IS_EMPTY(&opt.f_bssid))
	{
		printf("Notice: specify bssid \"--bssid\" with \"--netmask\"\n");
		printf("\"%s --help\" for help.\n", argv[0]);
		return (EXIT_FAILURE);
	}

	if (lopt.show_wps && lopt.show_manufacturer)
		lopt.maxsize_essid_seen += lopt.maxsize_wps_seen;

	if (lopt.s_iface != NULL)
	{
		/* initialize cards */
		lopt.num_cards = init_cards(lopt.s_iface, iface, wi);

		if (lopt.num_cards <= 0 || lopt.num_cards >= MAX_CARDS)
		{
			printf("Failed initializing wireless card(s): %s\n", lopt.s_iface);
			return EXIT_FAILURE;
		}

		for (i = 0; i < lopt.num_cards; i++)
		{
			fd_raw[i] = wi_fd(wi[i]);
			if (fd_raw[i] > fdh) fdh = fd_raw[i];
		}

		if (lopt.freqoption == 1 && lopt.freqstring != NULL) // use frequencies
		{
            struct detected_frequencies_st detected_frequencies; 

            detect_frequencies(wi[0], &detected_frequencies);

            lopt.frequency[0] = 
                getfrequencies(&detected_frequencies, lopt.freqstring);

            detected_frequencies_cleanup(&detected_frequencies); 

			if (lopt.frequency[0] == -1)
			{
				printf("No valid frequency given.\n");
				return (EXIT_FAILURE);
			}

			rearrange_frequencies();

			freq_count = getfreqcount(0);

			/* find the interface index */
			/* start a child to hop between frequencies */

			if (lopt.frequency[0] == 0)
			{
                start_frequency_hopper_process(&lopt, wi, freq_count);
			}
			else
			{
				for (i = 0; i < lopt.num_cards; i++)
				{
					wi_set_freq(wi[i], lopt.frequency[0]);
					lopt.frequency[i] = lopt.frequency[0];
				}
				lopt.singlefreq = 1;
			}
		}
		else // use channels
		{
			/* find the interface index */
			/* start a child to hop between channels */

			if (lopt.channel[0] == 0)
			{
				int const chan_count = get_channel_count(lopt.channels, 0);

                start_channel_hopper_process(&lopt, wi, chan_count);
			}
			else
			{
				for (i = 0; i < lopt.num_cards; i++)
				{
#ifdef CONFIG_LIBNL
					wi_set_ht_channel(wi[i], lopt.channel[0], lopt.htval);
#else
					wi_set_channel(wi[i], lopt.channel[0]);
#endif
					lopt.channel[i] = lopt.channel[0];
				}
				lopt.singlechan = 1;
			}
		}
	}

	/* Drop privileges */
	if (setuid(getuid()) == -1)
	{
		perror("setuid");
	}

	/* check if there is an input file */
	if (opt.s_file != NULL)
	{
        lopt.f_cap_in = fopen(opt.s_file, "rb");
        if (lopt.f_cap_in == NULL)
		{
			perror("open failed");
			return (EXIT_FAILURE);
		}

		n = sizeof(struct pcap_file_header);

		if (fread(&lopt.pfh_in, 1, (size_t) n, lopt.f_cap_in) != (size_t) n)
		{
			perror("fread(pcap file header) failed");
			return (EXIT_FAILURE);
		}

		if (lopt.pfh_in.magic != TCPDUMP_MAGIC
			&& lopt.pfh_in.magic != TCPDUMP_CIGAM)
		{
			fprintf(stderr,
					"\"%s\" isn't a pcap file (expected "
					"TCPDUMP_MAGIC).\n",
					opt.s_file);
			return (EXIT_FAILURE);
		}

		if (lopt.pfh_in.magic == TCPDUMP_CIGAM) SWAP32(lopt.pfh_in.linktype);

		if (lopt.pfh_in.linktype != LINKTYPE_IEEE802_11
			&& lopt.pfh_in.linktype != LINKTYPE_PRISM_HEADER
			&& lopt.pfh_in.linktype != LINKTYPE_RADIOTAP_HDR
			&& lopt.pfh_in.linktype != LINKTYPE_PPI_HDR)
		{
			fprintf(stderr,
					"Wrong linktype from pcap file header "
					"(expected LINKTYPE_IEEE802_11) -\n"
					"this doesn't look like a regular 802.11 "
					"capture.\n");
			return (EXIT_FAILURE);
		}
	}

	/* open or create the output files */

    if (opt.record_data)
    {
        if (dump_initialize_multi_format(lopt.dump_prefix, ivs_only))
        {
            return (EXIT_FAILURE);
        }
    }

    int const pipe_result = pipe(lopt.signal_event_pipe);
    IGNORE_NZ(pipe_result);

	struct sigaction action;
	action.sa_flags = 0;
	action.sa_handler = &sighandler;
	sigemptyset(&action.sa_mask);

	if (sigaction(SIGINT, &action, NULL) == -1) perror("sigaction(SIGINT)");
	if (sigaction(SIGSEGV, &action, NULL) == -1) perror("sigaction(SIGSEGV)");
	if (sigaction(SIGTERM, &action, NULL) == -1) perror("sigaction(SIGTERM)");
	if (sigaction(SIGWINCH, &action, NULL) == -1) perror("sigaction(SIGWINCH)");

    action.sa_flags = 0;
    action.sa_handler = &sigchld_handler;
    sigemptyset(&action.sa_mask); 
    if (sigaction(SIGCHLD, &action, NULL) == -1)
    {
        perror("sigaction(SIGCHLD)");
    }

	/* fill oui struct if ram is greater than 32 MB */
	if (get_ram_size() > MIN_RAM_SIZE_LOAD_OUI_RAM)
	{
        lopt.manufacturer_list = load_oui_file();
	}

	/* start the GPS tracker */

	if (opt.usegpsd)
	{
        if (pthread_create(&lopt.gps_tid, NULL, &gps_tracker_thread, &lopt.gps_thread_result) != 0)
		{
			perror("Could not create GPS thread");
			return (EXIT_FAILURE);
		}

		usleep(50000);
		waitpid(-1, NULL, WNOHANG);
	}

    if (!opt.output_format_wifi_scanner)
    {
        hide_cursor();
        erase_display(2);
    }

	start_time = time(NULL);
	tt1 = time(NULL);
	tt2 = time(NULL);
	gettimeofday(&tv3, NULL);
	gettimeofday(&tv4, NULL);

	lopt.batt = getBatteryString();

    lopt.elapsed_time = strdup("0 s");
    ALLEGE(lopt.elapsed_time != NULL);

	/* Create start time string for kismet netxml file */
    lopt.airodump_start_time = strdup(ctime(&start_time));
    ALLEGE(lopt.airodump_start_time != NULL);
    // remove new line
    if (strlen(lopt.airodump_start_time) > 0)
    {
        lopt.airodump_start_time[strlen(lopt.airodump_start_time) - 1] = 0;
    }

	// Do not start the interactive mode input thread if running in the
	// background
	if (lopt.background_mode == -1)
	{
		lopt.background_mode = is_background();
	}

	if (!lopt.background_mode
		&& pthread_create(&lopt.input_tid, NULL, (void *)input_thread, NULL)
			   != 0)
	{
		perror("pthread_create failed");
		return (EXIT_FAILURE);
	}

    update_window_size(&lopt.ws);

	while (1)
	{
        check_monitor_process(&lopt);
        check_for_signal_events(&lopt);
		aps_purge_old_packets(&lopt, BUFFER_TIME_MILLISECS); 

        if (lopt.do_exit)
        {
            break;
        }

		if (time(NULL) - tt1 >= lopt.file_write_interval)
		{
			/* update the output files */

			tt1 = time(NULL);

            if (opt.output_format_csv)
            {
				dump_write_csv(&lopt.ap_list[lopt.current_ap_list_index], 
							   &lopt.sta_list[lopt.current_sta_list_index], 
							   lopt.f_encrypt);
            }

            if (opt.output_format_wifi_scanner)
            {
				dump_write_wifi_scanner(&lopt.ap_list[lopt.current_ap_list_index],
										&lopt.sta_list[lopt.current_sta_list_index],
                                        lopt.f_encrypt,
                                        lopt.filter_seconds,
                                        lopt.file_reset_seconds,
                                        lopt.sys_name,
                                        lopt.loc_name);
            }

            if (opt.output_format_kismet_csv)
            {
				dump_write_kismet_csv(&lopt.ap_list[lopt.current_ap_list_index], 
									  &lopt.sta_list[lopt.current_sta_list_index],
									  lopt.f_encrypt);
            }

			if (opt.output_format_kismet_netxml)
				dump_write_kismet_netxml(&lopt.ap_list[lopt.current_ap_list_index],
										 &lopt.sta_list[lopt.current_sta_list_index],
										 lopt.f_encrypt,
										 lopt.airodump_start_time);
		}

		if (time(NULL) - tt2 > 5)
		{
			if (lopt.sort_by != SORT_BY_NOTHING)
			{
				/* sort the APs by power */
                acquire_sort_lock(&lopt); 

				dump_sort();

                release_sort_lock(&lopt);
			}

			/* update the battery state */
			tt2 = time(NULL);
            free(lopt.batt);
            lopt.batt = getBatteryString();

			/* update elapsed time */

			free(lopt.elapsed_time);
			lopt.elapsed_time = getStringTimeFromSec(difftime(tt2, start_time));

            flush_output_files();
		}

		gettimeofday(&tv1, NULL);

		cycle_time = 1000000UL * (tv1.tv_sec - tv3.tv_sec)
					 + (tv1.tv_usec - tv3.tv_usec);

		cycle_time2 = 1000000UL * (tv1.tv_sec - tv4.tv_sec)
					  + (tv1.tv_usec - tv4.tv_usec);

		if (lopt.active_scan_sim > 0
			&& cycle_time2 > lopt.active_scan_sim * 1000)
		{
			gettimeofday(&tv4, NULL);
			send_probe_requests(wi, lopt.num_cards);
		}

		if (cycle_time > 500000)
		{
			gettimeofday(&tv3, NULL);
			update_rx_quality();
			if (lopt.s_iface != NULL)
			{
				check_monitor(wi, fd_raw, &fdh, lopt.num_cards);
				if (lopt.singlechan) check_channel(wi, lopt.num_cards);
				if (lopt.singlefreq) check_frequency(wi, lopt.num_cards);
			}
		}
		if (opt.s_file != NULL)
		{
			static struct timeval prev_tv = {0, 0};

			/* Read one packet */
			n = sizeof(pkh);

			if (fread(&pkh, (size_t)n, 1, lopt.f_cap_in) != 1)
			{
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ Finished reading input file %s.",
						 opt.s_file);
				opt.s_file = NULL;
				continue;
			}

			if (lopt.pfh_in.magic == TCPDUMP_CIGAM)
			{
				SWAP32(pkh.caplen);
				SWAP32(pkh.len);
			}

			n = caplen = pkh.caplen;

			memset(buffer, 0, sizeof(buffer));
			h80211 = buffer;

			if (n <= 0 || n > (int) sizeof(buffer))
			{
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ Finished reading input file %s.",
						 opt.s_file);
				opt.s_file = NULL;
				continue;
			}

			if (fread(h80211, (size_t) n, 1, lopt.f_cap_in) != 1)
			{
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ Finished reading input file %s.",
						 opt.s_file);
				opt.s_file = NULL;
				continue;
			}

			if (lopt.pfh_in.linktype == LINKTYPE_PRISM_HEADER)
			{
				if (h80211[7] == 0x40)
				{
					n = 64;
					ri.ri_power = -((int32_t) load32_le(h80211 + 0x33));
					ri.ri_noise = (int32_t) load32_le(h80211 + 0x33 + 12);
					ri.ri_rate = load32_le(h80211 + 0x33 + 24) * 500000;
				}
				else
				{
					n = load32_le(h80211 + 4);
					ri.ri_mactime = load64_le(h80211 + 0x5C - 48);
					ri.ri_channel = load32_le(h80211 + 0x5C - 36);
					ri.ri_power = -((int32_t) load32_le(h80211 + 0x5C));
					ri.ri_noise = (int32_t) load32_le(h80211 + 0x5C + 12);
					ri.ri_rate = load32_le(h80211 + 0x5C + 24) * 500000;
				}

				if (n < 8 || n >= caplen) continue;

				memcpy(tmpbuf, h80211, (size_t) caplen);
				caplen -= n;
				memcpy(h80211, tmpbuf + n, (size_t) caplen);
			}

			if (lopt.pfh_in.linktype == LINKTYPE_RADIOTAP_HDR)
			{
				/* remove the radiotap header */

				n = load16_le(h80211 + 2);

				if (n <= 0 || n >= caplen) continue;

				int got_signal = 0;
				int got_noise = 0;
				struct ieee80211_radiotap_iterator iterator;
				struct ieee80211_radiotap_header * rthdr;

				rthdr = (struct ieee80211_radiotap_header *) h80211;

				if (ieee80211_radiotap_iterator_init(
						&iterator, rthdr, caplen, NULL)
					< 0)
					continue;

				/* go through the radiotap arguments we have been given
				 * by the driver
				 */

				while (ieee80211_radiotap_iterator_next(&iterator) >= 0)
				{
					switch (iterator.this_arg_index)
					{
						case IEEE80211_RADIOTAP_TSFT:
							ri.ri_mactime = le64_to_cpu(
								*((uint64_t *) iterator.this_arg));
							break;

						case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
							if (!got_signal)
							{
								if (*iterator.this_arg < 127)
									ri.ri_power = *iterator.this_arg;
								else
									ri.ri_power = *iterator.this_arg - 255;

								got_signal = 1;
							}
							break;

						case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
							if (!got_signal)
							{
								if (*iterator.this_arg < 127)
									ri.ri_power = *iterator.this_arg;
								else
									ri.ri_power = *iterator.this_arg - 255;

								got_signal = 1;
							}
							break;

						case IEEE80211_RADIOTAP_DBM_ANTNOISE:
							if (!got_noise)
							{
								if (*iterator.this_arg < 127)
									ri.ri_noise = *iterator.this_arg;
								else
									ri.ri_noise = *iterator.this_arg - 255;

								got_noise = 1;
							}
							break;

						case IEEE80211_RADIOTAP_DB_ANTNOISE:
							if (!got_noise)
							{
								if (*iterator.this_arg < 127)
									ri.ri_noise = *iterator.this_arg;
								else
									ri.ri_noise = *iterator.this_arg - 255;

								got_noise = 1;
							}
							break;

						case IEEE80211_RADIOTAP_ANTENNA:
							ri.ri_antenna = *iterator.this_arg;
							break;

						case IEEE80211_RADIOTAP_CHANNEL:
							ri.ri_channel = getChannelFromFrequency(
								le16toh(*(uint16_t *) iterator.this_arg));
							break;

						case IEEE80211_RADIOTAP_RATE:
							ri.ri_rate = (*iterator.this_arg) * 500000;
							break;
					}
				}

				memcpy(tmpbuf, h80211, (size_t) caplen);
				caplen -= n;
				memcpy(h80211, tmpbuf + n, (size_t) caplen);
			}

			if (lopt.pfh_in.linktype == LINKTYPE_PPI_HDR)
			{
				/* remove the PPI header */

				n = load16_le(h80211 + 2);

				if (n <= 0 || n >= caplen) continue;

				/* for a while Kismet logged broken PPI headers */
				if (n == 24 && load16_le(h80211 + 8) == 2) n = 32;

				if (n <= 0 || n >= caplen) continue; //-V560

				memcpy(tmpbuf, h80211, (size_t) caplen);
				caplen -= n;
				memcpy(h80211, tmpbuf + n, (size_t) caplen);
			}

			read_pkts++;

			if (lopt.relative_time && prev_tv.tv_sec != 0
				&& prev_tv.tv_usec != 0)
			{
				// handle delaying this packet
				struct timeval pkt_tv;
				pkt_tv.tv_sec = pkh.tv_sec;
				pkt_tv.tv_usec = pkh.tv_usec;

				const useconds_t usec_diff
					= (useconds_t) time_diff(&prev_tv, &pkt_tv);

				if (usec_diff > 0) usleep(usec_diff);
			}
			else if (read_pkts % 10 == 0)
				usleep(1);

			// track the packet's timestamp
			prev_tv.tv_sec = pkh.tv_sec;
			prev_tv.tv_usec = pkh.tv_usec;
		}
		else if (lopt.s_iface != NULL)
		{
			/* capture one packet */

			FD_ZERO(&rfds);
			for (i = 0; i < lopt.num_cards; i++)
			{
				FD_SET(fd_raw[i], &rfds); // NOLINT(hicpp-signed-bitwise)
			}

			tv0.tv_sec = lopt.update_s;
			tv0.tv_usec = (lopt.update_s == 0) ? REFRESH_RATE : 0;

			gettimeofday(&tv1, NULL);

			if (select(fdh + 1, &rfds, NULL, NULL, &tv0) < 0)
			{
				if (errno == EINTR)
				{
					gettimeofday(&tv2, NULL);

					time_slept += 1000000UL * (tv2.tv_sec - tv1.tv_sec)
								  + (tv2.tv_usec - tv1.tv_usec);

					continue;
				}
				perror("select failed");

				/* Restore terminal */
				show_cursor();

				return EXIT_FAILURE;
			}
		}
        else
        {
			usleep(1);
        }

		gettimeofday(&tv2, NULL);

		time_slept += 1000000UL * (tv2.tv_sec - tv1.tv_sec)
					  + (tv2.tv_usec - tv1.tv_usec);

        if (time_slept > REFRESH_RATE && time_slept > lopt.update_s * 1000000)
		{
			time_slept = 0;

			update_dataps();

            update_window_size(&lopt.ws);

			/* display the list of access points we have */

			if (!lopt.do_pause && !lopt.background_mode)
			{
                acquire_print_lock(&lopt);
				dump_print(lopt.ws.ws_row, lopt.ws.ws_col, lopt.num_cards);
                release_print_lock(&lopt);
            }
			continue;
		}

		if (opt.s_file == NULL && lopt.s_iface != NULL)
		{
			for (i = 0; i < lopt.num_cards; i++)
			{
				if (FD_ISSET(fd_raw[i], &rfds)) // NOLINT(hicpp-signed-bitwise)
				{

					memset(buffer, 0, sizeof(buffer));
					h80211 = buffer;
					if ((caplen = wi_read(
							 wi[i], NULL, NULL, h80211, sizeof(buffer), &ri))
						== -1)
					{
						wi_read_failed++;
						if (wi_read_failed > 1)
						{
							lopt.do_exit = 1;
							break;
						}
						snprintf(lopt.message,
								 sizeof(lopt.message),
								 "][ interface %s down ",
								 wi_get_ifname(wi[i]));

                        wi[i] = reopen_card(wi[i]);
						if (wi[i] == NULL)
						{
							/* Restore terminal */
							show_cursor();
							exit(EXIT_FAILURE);
						}

						fd_raw[i] = wi_fd(wi[i]);
						if (fd_raw[i] > fdh)
						{
							fdh = fd_raw[i];
						}

						break;
					}

					read_pkts++;

					wi_read_failed = 0;
					dump_add_packet(h80211, caplen, &ri, i);
				}
			}
		}
		else if (opt.s_file != NULL)
		{
			dump_add_packet(h80211, caplen, &ri, i);
		}

		if (quitting > 0 && (time(NULL) - quitting_event_ts) > 3)
		{
			quitting_event_ts = 0;
			quitting = 0;
			snprintf(lopt.message, sizeof(lopt.message), "]");
		}
	}

	signal_event_shutdown(&lopt); 

	free(lopt.batt);
	free(lopt.elapsed_time);
	free(lopt.own_channels);
	free(lopt.f_essid);
	free(opt.prefix);
	free(opt.f_cap_name);
	free(lopt.keyout);

#ifdef HAVE_PCRE
	if (lopt.f_essid_regex) pcre_free(lopt.f_essid_regex);
#endif

    for (i = 0; i < lopt.num_cards; i++)
    {
        wi_close(wi[i]);
    }

	if (opt.record_data)
	{
        if (opt.output_format_csv)
        {
			dump_write_csv(&lopt.ap_list[lopt.current_ap_list_index], 
						   &lopt.sta_list[lopt.current_sta_list_index], 
						   lopt.f_encrypt);
        }

        if (opt.output_format_wifi_scanner)
        {
			dump_write_wifi_scanner(&lopt.ap_list[lopt.current_ap_list_index],
									&lopt.sta_list[lopt.current_sta_list_index],
                                    lopt.f_encrypt, 
                                    lopt.filter_seconds, 
                                    lopt.file_reset_seconds,
                                    lopt.sys_name,
                                    lopt.loc_name);
        }

        if (opt.output_format_kismet_csv)
        {
			dump_write_kismet_csv(&lopt.ap_list[lopt.current_ap_list_index], 
								  &lopt.sta_list[lopt.current_sta_list_index],
								  lopt.f_encrypt);
        }

        if (opt.output_format_kismet_netxml)
        {
			dump_write_kismet_netxml(&lopt.ap_list[lopt.current_ap_list_index],
									 &lopt.sta_list[lopt.current_sta_list_index],
                                     lopt.f_encrypt,
                                     lopt.airodump_start_time);
        }

        if (opt.f_txt != NULL)
        {
            fclose(opt.f_txt);
        }

        if (opt.f_wifi != NULL)
        {
            fclose(opt.f_wifi);
        }

        free(opt.wifi_scanner_filename);
        opt.wifi_scanner_filename = NULL;

        if (opt.f_kis != NULL)
        {
			fclose(opt.f_kis);
        }

        if (opt.f_kis_xml != NULL)
        {
			fclose(opt.f_kis_xml);
        }

        free(lopt.airodump_start_time);
        lopt.airodump_start_time = NULL;

        if (opt.f_gps != NULL)
        {
            fclose(opt.f_gps);
        }

        if (opt.f_cap != NULL)
        {
             fclose(opt.f_cap);
        }

        if (opt.f_ivs != NULL)
        {
            fclose(opt.f_ivs);
        }

        if (opt.f_logcsv != NULL)
        {
            fclose(opt.f_logcsv);
        }
    }

	if (!lopt.save_gps)
	{
		snprintf((char *)buffer, sizeof buffer, "%s-%02d.gps", argv[2], opt.f_index);
		unlink((char *)buffer);
	}

	if (opt.usegpsd)
	{
		pthread_join(lopt.gps_tid, NULL);
	}

	if (!lopt.background_mode)
	{
		pthread_join(lopt.input_tid, NULL);
	}

	ap_list_free(&lopt.ap_list[lopt.current_ap_list_index]);

	sta_list_free(&lopt.sta_list[lopt.current_sta_list_index]);

	na_info_list_free(&lopt.na_list);

	oui_list_free(&lopt.manufacturer_list);

	reset_term();
	show_cursor();

	return EXIT_SUCCESS;
}
