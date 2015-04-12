/*
 *  pcap-compatible 802.11 packet sniffer
 *
 *  Copyright (C) 2006-2015 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/time.h>

#ifndef TIOCGWINSZ
	#include <sys/termios.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <fcntl.h>
#include <pthread.h>
#include <termios.h>

#include <sys/wait.h>

#ifdef HAVE_PCRE
#include <pcre.h>
#endif

#include "version.h"
#include "pcap.h"
#include "uniqueiv.h"
#include "crypto.h"
#include "osdep/osdep.h"
#include "airodump-ng.h"
#include "osdep/common.h"
#include "common.h"

#ifdef USE_GCRYPT
	GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif

// in common.c
extern int is_string_number(const char * str);

void dump_sort( void );
void dump_print( int ws_row, int ws_col, int if_num );

char * get_manufacturer_from_string(char * buffer) {
	char * manuf = NULL;
	char * buffer_manuf;
	if (buffer != NULL && strlen(buffer) > 0) {
		buffer_manuf = strstr(buffer, "(hex)");
		if (buffer_manuf != NULL) {
			buffer_manuf += 6; // skip '(hex)' and one more character (there's at least one 'space' character after that string)
			while (*buffer_manuf == '\t' || *buffer_manuf == ' ') {
				++buffer_manuf;
			}

			// Did we stop at the manufacturer
			if (*buffer_manuf != '\0') {

				// First make sure there's no end of line
				if (buffer_manuf[strlen(buffer_manuf) - 1] == '\n' || buffer_manuf[strlen(buffer_manuf) - 1] == '\r') {
					buffer_manuf[strlen(buffer_manuf) - 1] = '\0';
					if (*buffer_manuf != '\0' && (buffer_manuf[strlen(buffer_manuf) - 1] == '\n' || buffer[strlen(buffer_manuf) - 1] == '\r')) {
						buffer_manuf[strlen(buffer_manuf) - 1] = '\0';
					}
				}
				if (*buffer_manuf != '\0') {
					if ((manuf = (char *)malloc((strlen(buffer_manuf) + 1) * sizeof(char))) == NULL) {
						perror("malloc failed");
						return NULL;
					}
					snprintf(manuf, strlen(buffer_manuf) + 1, "%s", buffer_manuf);
				}
			}
		}
	}

	return manuf;
}

void textcolor(int attr, int fg, int bg)
{	char command[13];

	/* Command is the control command to the terminal */
	sprintf(command, "%c[%d;%d;%dm", 0x1B, attr, fg + 30, bg + 40);
	fprintf(stderr, "%s", command);
	fflush(stderr);
}

void textcolor_fg(int fg)
{	char command[13];

	/* Command is the control command to the terminal */
	sprintf(command, "\033[%dm", fg + 30);
	fprintf(stderr, "%s", command);
	fflush(stderr);
}

void textcolor_bg(int bg)
{	char command[13];

	/* Command is the control command to the terminal */
	sprintf(command, "\033[%dm", bg + 40);
	fprintf(stderr, "%s", command);
	fflush(stderr);
}

void textstyle(int attr)
{	char command[13];

	/* Command is the control command to the terminal */
	sprintf(command, "\033[%im", attr);
	fprintf(stderr, "%s", command);
	fflush(stderr);
}

void reset_term() {
  struct termios oldt,
                 newt;
  tcgetattr( STDIN_FILENO, &oldt );
  newt = oldt;
  newt.c_lflag |= ( ICANON | ECHO );
  tcsetattr( STDIN_FILENO, TCSANOW, &newt );
}

int mygetch( ) {
  struct termios oldt,
                 newt;
  int            ch;
  tcgetattr( STDIN_FILENO, &oldt );
  newt = oldt;
  newt.c_lflag &= ~( ICANON | ECHO );
  tcsetattr( STDIN_FILENO, TCSANOW, &newt );
  ch = getchar();
  tcsetattr( STDIN_FILENO, TCSANOW, &oldt );
  return ch;
}

void resetSelection()
{
    G.sort_by = SORT_BY_POWER;
    G.sort_inv = 1;

    G.start_print_ap=1;
    G.start_print_sta=1;
    G.selected_ap=1;
    G.selected_sta=1;
    G.selection_ap=0;
    G.selection_sta=0;
    G.mark_cur_ap=0;
    G.skip_columns=0;
    G.do_pause=0;
    G.do_sort_always=0;
    memset(G.selected_bssid, '\x00', 6);
}

#define KEY_TAB		0x09	//switch between APs/clients for scrolling
#define KEY_SPACE	0x20	//pause/resume output
#define KEY_ARROW_UP	0x41	//scroll
#define KEY_ARROW_DOWN	0x42	//scroll
#define KEY_ARROW_RIGHT 0x43	//scroll
#define KEY_ARROW_LEFT	0x44	//scroll
#define KEY_a		0x61	//cycle through active information (ap/sta/ap+sta/ap+sta+ack)
#define KEY_c		0x63	//cycle through channels
#define KEY_d		0x64	//default mode
#define KEY_i		0x69	//inverse sorting
#define KEY_m		0x6D	//mark current AP
#define KEY_n		0x6E	//?
#define KEY_r		0x72	//realtime sort (de)activate
#define KEY_s		0x73	//cycle through sorting

void input_thread( void *arg) {

    if(!arg){}

    while( G.do_exit == 0 ) {
	int keycode=0;

	keycode=mygetch();

	if(keycode == KEY_s) {
	    G.sort_by++;
	    G.selection_ap = 0;
	    G.selection_sta = 0;

	    if(G.sort_by > MAX_SORT)
		G.sort_by = 0;

	    switch(G.sort_by) {
		case SORT_BY_NOTHING:
		    snprintf(G.message, sizeof(G.message), "][ sorting by first seen");
		    break;
		case SORT_BY_BSSID:
		    snprintf(G.message, sizeof(G.message), "][ sorting by bssid");
		    break;
		case SORT_BY_POWER:
		    snprintf(G.message, sizeof(G.message), "][ sorting by power level");
		    break;
		case SORT_BY_BEACON:
		    snprintf(G.message, sizeof(G.message), "][ sorting by beacon number");
		    break;
		case SORT_BY_DATA:
		    snprintf(G.message, sizeof(G.message), "][ sorting by number of data packets");
		    break;
		case SORT_BY_PRATE:
		    snprintf(G.message, sizeof(G.message), "][ sorting by packet rate");
		    break;
		case SORT_BY_CHAN:
		    snprintf(G.message, sizeof(G.message), "][ sorting by channel");
		    break;
		case SORT_BY_MBIT:
		    snprintf(G.message, sizeof(G.message), "][ sorting by max data rate");
		    break;
		case SORT_BY_ENC:
		    snprintf(G.message, sizeof(G.message), "][ sorting by encryption");
		    break;
		case SORT_BY_CIPHER:
		    snprintf(G.message, sizeof(G.message), "][ sorting by cipher");
		    break;
		case SORT_BY_AUTH:
		    snprintf(G.message, sizeof(G.message), "][ sorting by authentication");
		    break;
		case SORT_BY_ESSID:
		    snprintf(G.message, sizeof(G.message), "][ sorting by ESSID");
		    break;
		default:
		    break;
	    }
	    pthread_mutex_lock( &(G.mx_sort) );
		dump_sort();
	    pthread_mutex_unlock( &(G.mx_sort) );
	}

	if(keycode == KEY_SPACE) {
	    G.do_pause = (G.do_pause+1)%2;
	    if(G.do_pause) {
		snprintf(G.message, sizeof(G.message), "][ paused output");
		pthread_mutex_lock( &(G.mx_print) );

		    fprintf( stderr, "\33[1;1H" );
		    dump_print( G.ws.ws_row, G.ws.ws_col, G.num_cards );
		    fprintf( stderr, "\33[J" );
		    fflush(stderr);

		pthread_mutex_unlock( &(G.mx_print) );
	    }
	    else
		snprintf(G.message, sizeof(G.message), "][ resumed output");
	}

	if(keycode == KEY_r) {
	    G.do_sort_always = (G.do_sort_always+1)%2;
	    if(G.do_sort_always)
		snprintf(G.message, sizeof(G.message), "][ realtime sorting activated");
	    else
		snprintf(G.message, sizeof(G.message), "][ realtime sorting deactivated");
	}

	if(keycode == KEY_m) {
	    G.mark_cur_ap = 1;
	}

	if(keycode == KEY_ARROW_DOWN) {
	    if(G.selection_ap == 1) {
		G.selected_ap++;
	    }
	    if(G.selection_sta == 1) {
		G.selected_sta++;
	    }
	}

	if(keycode == KEY_ARROW_UP) {
	    if(G.selection_ap == 1) {
		G.selected_ap--;
		if(G.selected_ap < 1)
		    G.selected_ap = 1;
	    }
	    if(G.selection_sta == 1) {
		G.selected_sta--;
		if(G.selected_sta < 1)
		    G.selected_sta = 1;
	    }
	}

	if(keycode == KEY_i) {
	    G.sort_inv*=-1;
	    if(G.sort_inv < 0)
		snprintf(G.message, sizeof(G.message), "][ inverted sorting order");
	    else
		snprintf(G.message, sizeof(G.message), "][ normal sorting order");
	}

	if(keycode == KEY_TAB) {
	    if(G.selection_ap == 0) {
		G.selection_ap = 1;
		G.selected_ap = 1;
		snprintf(G.message, sizeof(G.message), "][ enabled AP selection");
		G.sort_by = SORT_BY_NOTHING;
	    } else if(G.selection_ap == 1) {
		G.selection_ap = 0;
		G.sort_by = SORT_BY_NOTHING;
		snprintf(G.message, sizeof(G.message), "][ disabled selection");
	    }
	}

	if(keycode == KEY_a) {
	    if(G.show_ap == 1 && G.show_sta == 1 && G.show_ack == 0) {
		G.show_ap = 1;
		G.show_sta = 1;
		G.show_ack = 1;
		snprintf(G.message, sizeof(G.message), "][ display ap+sta+ack");
	    } else if(G.show_ap == 1 && G.show_sta == 1 && G.show_ack == 1) {
		G.show_ap = 1;
		G.show_sta = 0;
		G.show_ack = 0;
		snprintf(G.message, sizeof(G.message), "][ display ap only");
	    } else if(G.show_ap == 1 && G.show_sta == 0 && G.show_ack == 0) {
		G.show_ap = 0;
		G.show_sta = 1;
		G.show_ack = 0;
		snprintf(G.message, sizeof(G.message), "][ display sta only");
	    } else if(G.show_ap == 0 && G.show_sta == 1 && G.show_ack == 0) {
		G.show_ap = 1;
		G.show_sta = 1;
		G.show_ack = 0;
		snprintf(G.message, sizeof(G.message), "][ display ap+sta");
	    }
	}

	if (keycode == KEY_d) {
		resetSelection();
		snprintf(G.message, sizeof(G.message), "][ reset selection to default");
	}

	if(G.do_exit == 0 && !G.do_pause) {
	    pthread_mutex_lock( &(G.mx_print) );

		fprintf( stderr, "\33[1;1H" );
		dump_print( G.ws.ws_row, G.ws.ws_col, G.num_cards );
		fprintf( stderr, "\33[J" );
		fflush(stderr);

	    pthread_mutex_unlock( &(G.mx_print) );
	}
    }
}

void trim(char *str)
{
    int i;
    int begin = 0;
    int end = strlen(str) - 1;

    while (isspace((int)str[begin])) begin++;
    while ((end >= begin) && isspace((int)str[end])) end--;
    // Shift all characters back to the start of the string array.
    for (i = begin; i <= end; i++)
        str[i - begin] = str[i];
    str[i - begin] = '\0'; // Null terminate string.
}

FILE *open_oui_file(void) {
	int i;
	FILE *fp = NULL;

	for (i=0; OUI_PATHS[i] != NULL; i++) {
		fp = fopen(OUI_PATHS[i], "r");
		if ( fp != NULL ) {
			break;
		}
	}

	return fp;
}

struct oui * load_oui_file(void) {
	FILE *fp;
	char * manuf;
	char buffer[BUFSIZ];
	unsigned char a[2];
	unsigned char b[2];
	unsigned char c[2];
	struct oui *oui_ptr = NULL, *oui_head = NULL;
	
	fp = open_oui_file();
	if (!fp) {
		return NULL;
	}

	memset(buffer, 0x00, sizeof(buffer));
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		if (!(strstr(buffer, "(hex)")))
			continue;

		memset(a, 0x00, sizeof(a));
		memset(b, 0x00, sizeof(b));
		memset(c, 0x00, sizeof(c));
		// Remove leading/trailing whitespaces.
		trim(buffer);
		if (sscanf(buffer, "%2c-%2c-%2c", a, b, c) == 3) {
			if (oui_ptr == NULL) {
				if (!(oui_ptr = (struct oui *)malloc(sizeof(struct oui)))) {
					fclose(fp);
					perror("malloc failed");
					return NULL;
				}
			} else {
				if (!(oui_ptr->next = (struct oui *)malloc(sizeof(struct oui)))) {
					fclose(fp);
					perror("malloc failed");
					return NULL;
				}
				oui_ptr = oui_ptr->next;
			}
			memset(oui_ptr->id, 0x00, sizeof(oui_ptr->id));
			memset(oui_ptr->manuf, 0x00, sizeof(oui_ptr->manuf));
			snprintf(oui_ptr->id, sizeof(oui_ptr->id), "%c%c:%c%c:%c%c", a[0], a[1], b[0], b[1], c[0], c[1]);
			manuf = get_manufacturer_from_string(buffer);
			if (manuf != NULL) {
				snprintf(oui_ptr->manuf, sizeof(oui_ptr->manuf), "%s", manuf);
				free(manuf);
			} else {
				snprintf(oui_ptr->manuf, sizeof(oui_ptr->manuf), "Unknown");
			}
			if (oui_head == NULL)
				oui_head = oui_ptr;
			oui_ptr->next = NULL;
		}
	}

	fclose(fp);
	return oui_head;
}

int check_shared_key(unsigned char *h80211, int caplen)
{
    int m_bmac, m_smac, m_dmac, n, textlen;
    char ofn[1024];
    char text[4096];
    char prga[4096];
    unsigned int long crc;

    if((unsigned)caplen > sizeof(G.sharedkey[0])) return 1;

    m_bmac = 16;
    m_smac = 10;
    m_dmac = 4;

    if( time(NULL) - G.sk_start > 5)
    {
        /* timeout(5sec) - remove all packets, restart timer */
        memset(G.sharedkey, '\x00', 4096*3);
        G.sk_start = time(NULL);
    }

    /* is auth packet */
    if( (h80211[1] & 0x40) != 0x40 )
    {
        /* not encrypted */
        if( ( h80211[24] + (h80211[25] << 8) ) == 1 )
        {
            /* Shared-Key Authentication */
            if( ( h80211[26] + (h80211[27] << 8) ) == 2 )
            {
                /* sequence == 2 */
                memcpy(G.sharedkey[0], h80211, caplen);
                G.sk_len = caplen-24;
            }
            if( ( h80211[26] + (h80211[27] << 8) ) == 4 )
            {
                /* sequence == 4 */
                memcpy(G.sharedkey[2], h80211, caplen);
            }
        }
        else return 1;
    }
    else
    {
        /* encrypted */
        memcpy(G.sharedkey[1], h80211, caplen);
        G.sk_len2 = caplen-24-4;
    }

    /* check if the 3 packets form a proper authentication */

    if( ( memcmp(G.sharedkey[0]+m_bmac, NULL_MAC, 6) == 0 ) ||
        ( memcmp(G.sharedkey[1]+m_bmac, NULL_MAC, 6) == 0 ) ||
        ( memcmp(G.sharedkey[2]+m_bmac, NULL_MAC, 6) == 0 ) ) /* some bssids == zero */
    {
        return 1;
    }

    if( ( memcmp(G.sharedkey[0]+m_bmac, G.sharedkey[1]+m_bmac, 6) != 0 ) ||
        ( memcmp(G.sharedkey[0]+m_bmac, G.sharedkey[2]+m_bmac, 6) != 0 ) ) /* all bssids aren't equal */
    {
        return 1;
    }

    if( ( memcmp(G.sharedkey[0]+m_smac, G.sharedkey[2]+m_smac, 6) != 0 ) ||
        ( memcmp(G.sharedkey[0]+m_smac, G.sharedkey[1]+m_dmac, 6) != 0 ) ) /* SA in 2&4 != DA in 3 */
    {
        return 1;
    }

    if( (memcmp(G.sharedkey[0]+m_dmac, G.sharedkey[2]+m_dmac, 6) != 0 ) ||
        (memcmp(G.sharedkey[0]+m_dmac, G.sharedkey[1]+m_smac, 6) != 0 ) ) /* DA in 2&4 != SA in 3 */
    {
        return 1;
    }

    textlen = G.sk_len;

    if(textlen+4 != G.sk_len2)
    {
        snprintf(G.message, sizeof(G.message), "][ Broken SKA: %02X:%02X:%02X:%02X:%02X:%02X ",
                    *(G.sharedkey[0]+m_bmac), *(G.sharedkey[0]+m_bmac+1), *(G.sharedkey[0]+m_bmac+2),
                *(G.sharedkey[0]+m_bmac+3), *(G.sharedkey[0]+m_bmac+4), *(G.sharedkey[0]+m_bmac+5));
        return 1;
    }

    if((unsigned)textlen > sizeof(text) - 4) return 1;

    memcpy(text, G.sharedkey[0]+24, textlen);

    /* increment sequence number from 2 to 3 */
    text[2] = text[2]+1;

    crc = 0xFFFFFFFF;

    for( n = 0; n < textlen; n++ )
        crc = crc_tbl[(crc ^ text[n]) & 0xFF] ^ (crc >> 8);

    crc = ~crc;

    /* append crc32 over body */
    text[textlen]     = (crc      ) & 0xFF;
    text[textlen+1]   = (crc >>  8) & 0xFF;
    text[textlen+2]   = (crc >> 16) & 0xFF;
    text[textlen+3]   = (crc >> 24) & 0xFF;

    /* cleartext XOR cipher */
    for(n=0; n<(textlen+4); n++)
    {
        prga[4+n] = (text[n] ^ G.sharedkey[1][28+n]) & 0xFF;
    }

    /* write IV+index */
    prga[0] = G.sharedkey[1][24] & 0xFF;
    prga[1] = G.sharedkey[1][25] & 0xFF;
    prga[2] = G.sharedkey[1][26] & 0xFF;
    prga[3] = G.sharedkey[1][27] & 0xFF;

    if( G.f_xor != NULL )
    {
        fclose(G.f_xor);
        G.f_xor = NULL;
    }

    snprintf( ofn, sizeof( ofn ) - 1, "%s-%02d-%02X-%02X-%02X-%02X-%02X-%02X.%s", G.prefix, G.f_index,
              *(G.sharedkey[0]+m_bmac), *(G.sharedkey[0]+m_bmac+1), *(G.sharedkey[0]+m_bmac+2),
              *(G.sharedkey[0]+m_bmac+3), *(G.sharedkey[0]+m_bmac+4), *(G.sharedkey[0]+m_bmac+5), "xor" );

    G.f_xor = fopen( ofn, "w");
    if(G.f_xor == NULL)
        return 1;

    for(n=0; n<textlen+8; n++)
        fputc((prga[n] & 0xFF), G.f_xor);

    fflush(G.f_xor);

    if( G.f_xor != NULL )
    {
        fclose(G.f_xor);
        G.f_xor = NULL;
    }

    snprintf(G.message, sizeof(G.message), "][ %d bytes keystream: %02X:%02X:%02X:%02X:%02X:%02X ",
                textlen+4, *(G.sharedkey[0]+m_bmac), *(G.sharedkey[0]+m_bmac+1), *(G.sharedkey[0]+m_bmac+2),
              *(G.sharedkey[0]+m_bmac+3), *(G.sharedkey[0]+m_bmac+4), *(G.sharedkey[0]+m_bmac+5));

    memset(G.sharedkey, '\x00', 512*3);
    /* ok, keystream saved */
    return 0;
}

char usage[] =

"\n"
"  %s - (C) 2006-2015 Thomas d\'Otreppe\n"
"  http://www.aircrack-ng.org\n"
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
"      -x            <msecs> : Active Scanning Simulation\n"
"      --manufacturer        : Display manufacturer from IEEE OUI list\n"
"      --uptime              : Display AP Uptime from Beacon Timestamp\n"
"      --wps                 : Display WPS information (if any)\n"
"      --output-format\n"
"                  <formats> : Output format. Possible values:\n"
"                              pcap, ivs, csv, gps, kismet, netxml\n"
"      --ignore-negative-one : Removes the message that says\n"
"                              fixed channel <interface>: -1\n"
"      --write-interval\n"
"                  <seconds> : Output file(s) write interval in seconds\n"
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
"  By default, airodump-ng hop on 2.4GHz channels.\n"
"  You can make it capture on other/specific channel(s) by using:\n"
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

int is_filtered_netmask(unsigned char *bssid)
{
    unsigned char mac1[6];
    unsigned char mac2[6];
    int i;

    for(i=0; i<6; i++)
    {
        mac1[i] = bssid[i]     & G.f_netmask[i];
        mac2[i] = G.f_bssid[i] & G.f_netmask[i];
    }

    if( memcmp(mac1, mac2, 6) != 0 )
    {
        return( 1 );
    }

    return 0;
}

int is_filtered_essid(unsigned char *essid)
{
    int ret = 0;
    int i;

    if(G.f_essid)
    {
        for(i=0; i<G.f_essid_count; i++)
        {
            if(strncmp((char*)essid, G.f_essid[i], MAX_IE_ELEMENT_SIZE) == 0)
            {
                return 0;
            }
        }

        ret = 1;
    }

#ifdef HAVE_PCRE
    if(G.f_essid_regex)
    {
        return pcre_exec(G.f_essid_regex, NULL, (char*)essid, strnlen((char *)essid, MAX_IE_ELEMENT_SIZE), 0, 0, NULL, 0) < 0;
    }
#endif

    return ret;
}

void update_rx_quality( )
{
    unsigned int time_diff, capt_time, miss_time;
    int missed_frames;
    struct AP_info *ap_cur = NULL;
    struct ST_info *st_cur = NULL;
    struct timeval cur_time;

    ap_cur = G.ap_1st;
    st_cur = G.st_1st;

    gettimeofday( &cur_time, NULL );

    /* accesspoints */
    while( ap_cur != NULL )
    {
        time_diff = 1000000UL * (cur_time.tv_sec  - ap_cur->ftimer.tv_sec )
                            + (cur_time.tv_usec - ap_cur->ftimer.tv_usec);

        /* update every `QLT_TIME`seconds if the rate is low, or every 500ms otherwise */
        if( (ap_cur->fcapt >= QLT_COUNT && time_diff > 500000 ) || time_diff > (QLT_TIME * 1000000) )
        {
            /* at least one frame captured */
            if(ap_cur->fcapt > 1)
            {
                capt_time =   ( 1000000UL * (ap_cur->ftimel.tv_sec  - ap_cur->ftimef.tv_sec )    //time between first and last captured frame
                                        + (ap_cur->ftimel.tv_usec - ap_cur->ftimef.tv_usec) );

                miss_time =   ( 1000000UL * (ap_cur->ftimef.tv_sec  - ap_cur->ftimer.tv_sec )    //time between timer reset and first frame
                                        + (ap_cur->ftimef.tv_usec - ap_cur->ftimer.tv_usec) )
                            + ( 1000000UL * (cur_time.tv_sec  - ap_cur->ftimel.tv_sec )          //time between last frame and this moment
                                        + (cur_time.tv_usec - ap_cur->ftimel.tv_usec) );

                //number of frames missed at the time where no frames were captured; extrapolated by assuming a constant framerate
                if(capt_time > 0 && miss_time > 200000)
                {
                    missed_frames = ((float)((float)miss_time/(float)capt_time) * ((float)ap_cur->fcapt + (float)ap_cur->fmiss));
                    ap_cur->fmiss += missed_frames;
                }

                ap_cur->rx_quality = ((float)((float)ap_cur->fcapt / ((float)ap_cur->fcapt + (float)ap_cur->fmiss)) * 100.0);
            }
            else ap_cur->rx_quality = 0; /* no packets -> zero quality */

            /* normalize, in case the seq numbers are not iterating */
            if(ap_cur->rx_quality > 100) ap_cur->rx_quality = 100;
            if(ap_cur->rx_quality < 0  ) ap_cur->rx_quality =   0;

            /* reset variables */
            ap_cur->fcapt = 0;
            ap_cur->fmiss = 0;
            gettimeofday( &(ap_cur->ftimer) ,NULL);
        }
        ap_cur = ap_cur->next;
    }

    /* stations */
    while( st_cur != NULL )
    {
        time_diff = 1000000UL * (cur_time.tv_sec  - st_cur->ftimer.tv_sec )
                            + (cur_time.tv_usec - st_cur->ftimer.tv_usec);

        if( time_diff > 10000000 )
        {
            st_cur->missed = 0;
            gettimeofday( &(st_cur->ftimer), NULL );
        }

        st_cur = st_cur->next;
    }

}

/* setup the output files */

int dump_initialize( char *prefix, int ivs_only )
{
    int i, ofn_len;
    FILE *f;
    char * ofn = NULL;


    /* If you only want to see what happening, send all data to /dev/null */

    if ( prefix == NULL || strlen( prefix ) == 0) {
	    return( 0 );
    }

	/* Create a buffer of the length of the prefix + '-' + 2 numbers + '.'
	   + longest extension ("kismet.netxml") + terminating 0. */
	ofn_len = strlen(prefix) + 1 + 2 + 1 + 13 + 1;
	ofn = (char *)calloc(1, ofn_len);

    G.f_index = 1;


	/* Make sure no file with the same name & all possible file extensions. */
    do
    {
        for( i = 0; i < NB_EXTENSIONS; i++ )
        {
			memset(ofn, 0, ofn_len);
            snprintf( ofn,  ofn_len, "%s-%02d.%s",
                      prefix, G.f_index, f_ext[i] );

            if( ( f = fopen( ofn, "rb+" ) ) != NULL )
            {
                fclose( f );
                G.f_index++;
                break;
            }
        }
    }
    /* If we did all extensions then no file with that name or extension exist
       so we can use that number */
    while( i < NB_EXTENSIONS );

    G.prefix = (char *) malloc(strlen(prefix) + 1);
    memcpy(G.prefix, prefix, strlen(prefix) + 1);

    /* create the output CSV file */

	if (G.output_format_csv) {
		memset(ofn, 0, ofn_len);
		snprintf( ofn,  ofn_len, "%s-%02d.%s",
				  prefix, G.f_index, AIRODUMP_NG_CSV_EXT );

		if( ( G.f_txt = fopen( ofn, "wb+" ) ) == NULL )
		{
			perror( "fopen failed" );
			fprintf( stderr, "Could not create \"%s\".\n", ofn );
			free( ofn );
			return( 1 );
		}
	}

    /* create the output Kismet CSV file */
	if (G.output_format_kismet_csv) {
		memset(ofn, 0, ofn_len);
		snprintf( ofn,  ofn_len, "%s-%02d.%s",
				  prefix, G.f_index, KISMET_CSV_EXT );

		if( ( G.f_kis = fopen( ofn, "wb+" ) ) == NULL )
		{
			perror( "fopen failed" );
			fprintf( stderr, "Could not create \"%s\".\n", ofn );
			free( ofn );
			return( 1 );
		}
	}

	/* create the output GPS file */

    if (G.usegpsd)
    {
        memset(ofn, 0, ofn_len);
        snprintf( ofn,  ofn_len, "%s-%02d.%s",
                  prefix, G.f_index, AIRODUMP_NG_GPS_EXT );

        if( ( G.f_gps = fopen( ofn, "wb+" ) ) == NULL )
        {
            perror( "fopen failed" );
            fprintf( stderr, "Could not create \"%s\".\n", ofn );
            free( ofn );
            return( 1 );
        }
    }

    /* Create the output kismet.netxml file */

	if (G.output_format_kismet_netxml) {
		memset(ofn, 0, ofn_len);
		snprintf( ofn,  ofn_len, "%s-%02d.%s",
				  prefix, G.f_index, KISMET_NETXML_EXT );

		if( ( G.f_kis_xml = fopen( ofn, "wb+" ) ) == NULL )
		{
			perror( "fopen failed" );
			fprintf( stderr, "Could not create \"%s\".\n", ofn );
			free( ofn );
			return( 1 );
		}
	}

    /* create the output packet capture file */
    if( G.output_format_pcap )
    {
        struct pcap_file_header pfh;

        memset(ofn, 0, ofn_len);
        snprintf( ofn,  ofn_len, "%s-%02d.%s",
                  prefix, G.f_index, AIRODUMP_NG_CAP_EXT );

        if( ( G.f_cap = fopen( ofn, "wb+" ) ) == NULL )
        {
            perror( "fopen failed" );
            fprintf( stderr, "Could not create \"%s\".\n", ofn );
            free( ofn );
            return( 1 );
        }

        G.f_cap_name = (char *) malloc( strlen( ofn ) + 1 );
        memcpy( G.f_cap_name, ofn, strlen( ofn ) + 1 );
        free( ofn );

        pfh.magic           = TCPDUMP_MAGIC;
        pfh.version_major   = PCAP_VERSION_MAJOR;
        pfh.version_minor   = PCAP_VERSION_MINOR;
        pfh.thiszone        = 0;
        pfh.sigfigs         = 0;
        pfh.snaplen         = 65535;
        pfh.linktype        = LINKTYPE_IEEE802_11;

        if( fwrite( &pfh, 1, sizeof( pfh ), G.f_cap ) !=
                    (size_t) sizeof( pfh ) )
        {
            perror( "fwrite(pcap file header) failed" );
            return( 1 );
        }
    } else if ( ivs_only ) {
        struct ivs2_filehdr fivs2;

        fivs2.version = IVS2_VERSION;

        memset(ofn, 0, ofn_len);
        snprintf( ofn,  ofn_len, "%s-%02d.%s",
                  prefix, G.f_index, IVS2_EXTENSION );

        if( ( G.f_ivs = fopen( ofn, "wb+" ) ) == NULL )
        {
            perror( "fopen failed" );
            fprintf( stderr, "Could not create \"%s\".\n", ofn );
            free( ofn );
            return( 1 );
        }
        free( ofn );

        if( fwrite( IVS2_MAGIC, 1, 4, G.f_ivs ) != (size_t) 4 )
        {
            perror( "fwrite(IVs file MAGIC) failed" );
            return( 1 );
        }

        if( fwrite( &fivs2, 1, sizeof(struct ivs2_filehdr), G.f_ivs ) != (size_t) sizeof(struct ivs2_filehdr) )
        {
            perror( "fwrite(IVs file header) failed" );
            return( 1 );
        }
    }

    return( 0 );
}

int update_dataps()
{
    struct timeval tv;
    struct AP_info *ap_cur;
    struct NA_info *na_cur;
    int sec, usec, diff, ps;
    float pause;

    gettimeofday(&tv, NULL);

    ap_cur = G.ap_end;

    while( ap_cur != NULL )
    {
        sec = (tv.tv_sec - ap_cur->tv.tv_sec);
        usec = (tv.tv_usec - ap_cur->tv.tv_usec);
        pause = (((float)(sec*1000000.0f + usec))/(1000000.0f));
        if( pause > 2.0f )
        {
            diff = ap_cur->nb_data - ap_cur->nb_data_old;
            ps = (int)(((float)diff)/pause);
            ap_cur->nb_dataps = ps;
            ap_cur->nb_data_old = ap_cur->nb_data;
            gettimeofday(&(ap_cur->tv), NULL);
        }
        ap_cur = ap_cur->prev;
    }

    na_cur = G.na_1st;

    while( na_cur != NULL )
    {
        sec = (tv.tv_sec - na_cur->tv.tv_sec);
        usec = (tv.tv_usec - na_cur->tv.tv_usec);
        pause = (((float)(sec*1000000.0f + usec))/(1000000.0f));
        if( pause > 2.0f )
        {
            diff = na_cur->ack - na_cur->ack_old;
            ps = (int)(((float)diff)/pause);
            na_cur->ackps = ps;
            na_cur->ack_old = na_cur->ack;
            gettimeofday(&(na_cur->tv), NULL);
        }
        na_cur = na_cur->next;
    }
    return(0);
}

int list_tail_free(struct pkt_buf **list)
{
    struct pkt_buf **pkts;
    struct pkt_buf *next;

    if(list == NULL) return 1;

    pkts = list;

    while(*pkts != NULL)
    {
        next = (*pkts)->next;
        if( (*pkts)->packet )
        {
            free( (*pkts)->packet);
            (*pkts)->packet=NULL;
        }

        if(*pkts)
        {
            free(*pkts);
            *pkts = NULL;
        }
        *pkts = next;
    }

    *list=NULL;

    return 0;
}

int list_add_packet(struct pkt_buf **list, int length, unsigned char* packet)
{
    struct pkt_buf *next = *list;

    if(length <= 0) return 1;
    if(packet == NULL) return 1;
    if(list == NULL) return 1;

    *list = (struct pkt_buf*) malloc(sizeof(struct pkt_buf));
    if( *list == NULL ) return 1;
    (*list)->packet = (unsigned char*) malloc(length);
    if( (*list)->packet == NULL ) return 1;

    memcpy((*list)->packet,  packet, length);
    (*list)->next = next;
    (*list)->length = length;
    gettimeofday( &((*list)->ctime), NULL);

    return 0;
}

/*
 * Check if the same IV was used if the first two bytes were the same.
 * If they are not identical, it would complain.
 * The reason is that the first two bytes unencrypted are 'aa'
 * so with the same IV it should always be encrypted to the same thing.
 */
int list_check_decloak(struct pkt_buf **list, int length, unsigned char* packet)
{
    struct pkt_buf *next = *list;
    struct timeval tv1;
    int timediff;
    int i, correct;

    if( packet == NULL) return 1;
    if( list == NULL ) return 1;
    if( *list == NULL ) return 1;
    if( length <= 0) return 1;

    gettimeofday(&tv1, NULL);

    timediff = (((tv1.tv_sec - ((*list)->ctime.tv_sec)) * 1000000UL) + (tv1.tv_usec - ((*list)->ctime.tv_usec))) / 1000;
    if( timediff > BUFFER_TIME )
    {
        list_tail_free(list);
        next=NULL;
    }

    while(next != NULL)
    {
        if(next->next != NULL)
        {
            timediff = (((tv1.tv_sec - (next->next->ctime.tv_sec)) * 1000000UL) + (tv1.tv_usec - (next->next->ctime.tv_usec))) / 1000;
            if( timediff > BUFFER_TIME )
            {
                list_tail_free(&(next->next));
                break;
            }
        }
        if( (next->length + 4) == length)
        {
            correct = 1;
            // check for 4 bytes added after the end
            for(i=28;i<length-28;i++)   //check everything (in the old packet) after the IV (including crc32 at the end)
            {
                if(next->packet[i] != packet[i])
                {
                    correct = 0;
                    break;
                }
            }
            if(!correct)
            {
                correct = 1;
                // check for 4 bytes added at the beginning
                for(i=28;i<length-28;i++)   //check everything (in the old packet) after the IV (including crc32 at the end)
                {
                    if(next->packet[i] != packet[4+i])
                    {
                        correct = 0;
                        break;
                    }
                }
            }
            if(correct == 1)
                    return 0;   //found decloaking!
        }
        next = next->next;
    }

    return 1; //didn't find decloak
}

int remove_namac(unsigned char* mac)
{
    struct NA_info *na_cur = NULL;
    struct NA_info *na_prv = NULL;

    if(mac == NULL)
        return( -1 );

    na_cur = G.na_1st;
    na_prv = NULL;

    while( na_cur != NULL )
    {
        if( ! memcmp( na_cur->namac, mac, 6 ) )
            break;

        na_prv = na_cur;
        na_cur = na_cur->next;
    }

    /* if it's known, remove it */
    if( na_cur != NULL )
    {
        /* first in linked list */
        if(na_cur == G.na_1st)
        {
            G.na_1st = na_cur->next;
        }
        else
        {
            na_prv->next = na_cur->next;
        }
        free(na_cur);
        na_cur=NULL;
    }

    return( 0 );
}

int dump_add_packet( unsigned char *h80211, int caplen, struct rx_info *ri, int cardnum )
{
    int i, n, seq, msd, dlen, offset, clen, o;
    unsigned z;
    int type, length, numuni=0, numauth=0;
    struct pcap_pkthdr pkh;
    struct timeval tv;
    struct ivs2_pkthdr ivs2;
    unsigned char *p, *org_p, c;
    unsigned char bssid[6];
    unsigned char stmac[6];
    unsigned char namac[6];
    unsigned char clear[2048];
    int weight[16];
    int num_xor=0;

    struct AP_info *ap_cur = NULL;
    struct ST_info *st_cur = NULL;
    struct NA_info *na_cur = NULL;
    struct AP_info *ap_prv = NULL;
    struct ST_info *st_prv = NULL;
    struct NA_info *na_prv = NULL;

    /* skip all non probe response frames in active scanning simulation mode */
    if( G.active_scan_sim > 0 && h80211[0] != 0x50 )
        return(0);

    /* skip packets smaller than a 802.11 header */

    if( caplen < 24 )
        goto write_packet;

    /* skip (uninteresting) control frames */

    if( ( h80211[0] & 0x0C ) == 0x04 )
        goto write_packet;

    /* if it's a LLC null packet, just forget it (may change in the future) */

    if ( caplen > 28)
        if ( memcmp(h80211 + 24, llcnull, 4) == 0)
            return ( 0 );

    /* grab the sequence number */
    seq = ((h80211[22]>>4)+(h80211[23]<<4));

    /* locate the access point's MAC address */

    switch( h80211[1] & 3 )
    {
        case  0: memcpy( bssid, h80211 + 16, 6 ); break;  //Adhoc
        case  1: memcpy( bssid, h80211 +  4, 6 ); break;  //ToDS
        case  2: memcpy( bssid, h80211 + 10, 6 ); break;  //FromDS
        case  3: memcpy( bssid, h80211 + 10, 6 ); break;  //WDS -> Transmitter taken as BSSID
    }

    if( memcmp(G.f_bssid, NULL_MAC, 6) != 0 )
    {
        if( memcmp(G.f_netmask, NULL_MAC, 6) != 0 )
        {
            if(is_filtered_netmask(bssid)) return(1);
        }
        else
        {
            if( memcmp(G.f_bssid, bssid, 6) != 0 ) return(1);
        }
    }

    /* update our chained list of access points */

    ap_cur = G.ap_1st;
    ap_prv = NULL;

    while( ap_cur != NULL )
    {
        if( ! memcmp( ap_cur->bssid, bssid, 6 ) )
            break;

        ap_prv = ap_cur;
        ap_cur = ap_cur->next;
    }

    /* if it's a new access point, add it */

    if( ap_cur == NULL )
    {
        if( ! ( ap_cur = (struct AP_info *) malloc(
                         sizeof( struct AP_info ) ) ) )
        {
            perror( "malloc failed" );
            return( 1 );
        }

        /* if mac is listed as unknown, remove it */
        remove_namac(bssid);

        memset( ap_cur, 0, sizeof( struct AP_info ) );

        if( G.ap_1st == NULL )
            G.ap_1st = ap_cur;
        else
            ap_prv->next  = ap_cur;

        memcpy( ap_cur->bssid, bssid, 6 );
		if (ap_cur->manuf == NULL) {
			ap_cur->manuf = get_manufacturer(ap_cur->bssid[0], ap_cur->bssid[1], ap_cur->bssid[2]);
		}

	ap_cur->nb_pkt = 0;
        ap_cur->prev = ap_prv;

        ap_cur->tinit = time( NULL );
        ap_cur->tlast = time( NULL );

        ap_cur->avg_power   = -1;
        ap_cur->best_power  = -1;
        ap_cur->power_index = -1;

        for( i = 0; i < NB_PWR; i++ )
            ap_cur->power_lvl[i] = -1;

        ap_cur->channel    = -1;
        ap_cur->max_speed  = -1;
        ap_cur->security   = 0;

        ap_cur->uiv_root = uniqueiv_init();

	ap_cur->nb_data = 0;
        ap_cur->nb_dataps = 0;
        ap_cur->nb_data_old = 0;
        gettimeofday(&(ap_cur->tv), NULL);

        ap_cur->dict_started = 0;

        ap_cur->key = NULL;

        G.ap_end = ap_cur;

        ap_cur->nb_bcn     = 0;

        ap_cur->rx_quality = 0;
        ap_cur->fcapt      = 0;
        ap_cur->fmiss      = 0;
        ap_cur->last_seq   = 0;
        gettimeofday( &(ap_cur->ftimef), NULL);
        gettimeofday( &(ap_cur->ftimel), NULL);
        gettimeofday( &(ap_cur->ftimer), NULL);

        ap_cur->ssid_length = 0;
        ap_cur->essid_stored = 0;
        memset( ap_cur->essid, 0, MAX_IE_ELEMENT_SIZE );
        ap_cur->timestamp = 0;

        ap_cur->decloak_detect=G.decloak;
        ap_cur->is_decloak = 0;
        ap_cur->packets = NULL;

	ap_cur->marked = 0;
	ap_cur->marked_color = 1;

        ap_cur->data_root = NULL;
        ap_cur->EAP_detected = 0;
        memcpy(ap_cur->gps_loc_min, G.gps_loc, sizeof(float)*5);
        memcpy(ap_cur->gps_loc_max, G.gps_loc, sizeof(float)*5);
        memcpy(ap_cur->gps_loc_best, G.gps_loc, sizeof(float)*5);
    }

    /* update the last time seen */

    ap_cur->tlast = time( NULL );

    /* only update power if packets comes from
     * the AP: either type == mgmt and SA != BSSID,
     * or FromDS == 1 and ToDS == 0 */

    if( ( ( h80211[1] & 3 ) == 0 &&
            memcmp( h80211 + 10, bssid, 6 ) == 0 ) ||
        ( ( h80211[1] & 3 ) == 2 ) )
    {
        ap_cur->power_index = ( ap_cur->power_index + 1 ) % NB_PWR;
        ap_cur->power_lvl[ap_cur->power_index] = ri->ri_power;

        ap_cur->avg_power = 0;

        for( i = 0, n = 0; i < NB_PWR; i++ )
        {
            if( ap_cur->power_lvl[i] != -1 )
            {
                ap_cur->avg_power += ap_cur->power_lvl[i];
                n++;
            }
        }

        if( n > 0 )
        {
            ap_cur->avg_power /= n;
            if( ap_cur->avg_power > ap_cur->best_power )
            {
                ap_cur->best_power = ap_cur->avg_power;
                memcpy(ap_cur->gps_loc_best, G.gps_loc, sizeof(float)*5);
            }
        }
        else
            ap_cur->avg_power = -1;

        /* every packet in here comes from the AP */

        if(G.gps_loc[0] > ap_cur->gps_loc_max[0])
            ap_cur->gps_loc_max[0] = G.gps_loc[0];
        if(G.gps_loc[1] > ap_cur->gps_loc_max[1])
            ap_cur->gps_loc_max[1] = G.gps_loc[1];
        if(G.gps_loc[2] > ap_cur->gps_loc_max[2])
            ap_cur->gps_loc_max[2] = G.gps_loc[2];

        if(G.gps_loc[0] < ap_cur->gps_loc_min[0])
            ap_cur->gps_loc_min[0] = G.gps_loc[0];
        if(G.gps_loc[1] < ap_cur->gps_loc_min[1])
            ap_cur->gps_loc_min[1] = G.gps_loc[1];
        if(G.gps_loc[2] < ap_cur->gps_loc_min[2])
            ap_cur->gps_loc_min[2] = G.gps_loc[2];
//        printf("seqnum: %i\n", seq);

        if(ap_cur->fcapt == 0 && ap_cur->fmiss == 0) gettimeofday( &(ap_cur->ftimef), NULL);
        if(ap_cur->last_seq != 0) ap_cur->fmiss += (seq - ap_cur->last_seq - 1);
        ap_cur->last_seq = seq;
        ap_cur->fcapt++;
        gettimeofday( &(ap_cur->ftimel), NULL);

//         if(ap_cur->fcapt >= QLT_COUNT) update_rx_quality();
    }

    switch( h80211[0] )
    {
        case  0x80:
            ap_cur->nb_bcn++;
        case  0x50:
            /* reset the WPS state */
            ap_cur->wps.state = 0xFF;
            ap_cur->wps.ap_setup_locked = 0;
            break;
    }

    ap_cur->nb_pkt++;

    /* find wpa handshake */
    if( h80211[0] == 0x10 )
    {
        /* reset the WPA handshake state */

        if( st_cur != NULL && st_cur->wpa.state != 0xFF )
            st_cur->wpa.state = 0;
//        printf("initial auth %d\n", ap_cur->wpa_state);
    }

    /* locate the station MAC in the 802.11 header */

    switch( h80211[1] & 3 )
    {
        case  0:

            /* if management, check that SA != BSSID */

            if( memcmp( h80211 + 10, bssid, 6 ) == 0 )
                goto skip_station;

            memcpy( stmac, h80211 + 10, 6 );
            break;

        case  1:

            /* ToDS packet, must come from a client */

            memcpy( stmac, h80211 + 10, 6 );
            break;

        case  2:

            /* FromDS packet, reject broadcast MACs */

            if( (h80211[4]%2) != 0 ) goto skip_station;
            memcpy( stmac, h80211 +  4, 6 ); break;

        default: goto skip_station;
    }

    /* update our chained list of wireless stations */

    st_cur = G.st_1st;
    st_prv = NULL;

    while( st_cur != NULL )
    {
        if( ! memcmp( st_cur->stmac, stmac, 6 ) )
            break;

        st_prv = st_cur;
        st_cur = st_cur->next;
    }

    /* if it's a new client, add it */

    if( st_cur == NULL )
    {
        if( ! ( st_cur = (struct ST_info *) malloc(
                         sizeof( struct ST_info ) ) ) )
        {
            perror( "malloc failed" );
            return( 1 );
        }

        /* if mac is listed as unknown, remove it */
        remove_namac(stmac);

        memset( st_cur, 0, sizeof( struct ST_info ) );

        if( G.st_1st == NULL )
            G.st_1st = st_cur;
        else
            st_prv->next  = st_cur;

        memcpy( st_cur->stmac, stmac, 6 );

		if (st_cur->manuf == NULL) {
			st_cur->manuf = get_manufacturer(st_cur->stmac[0], st_cur->stmac[1], st_cur->stmac[2]);
		}

	st_cur->nb_pkt = 0;

        st_cur->prev = st_prv;

        st_cur->tinit = time( NULL );
        st_cur->tlast = time( NULL );

        st_cur->power = -1;
        st_cur->rate_to = -1;
        st_cur->rate_from = -1;

        st_cur->probe_index = -1;
        st_cur->missed  = 0;
        st_cur->lastseq = 0;
        st_cur->qos_fr_ds = 0;
        st_cur->qos_to_ds = 0;
	st_cur->channel = 0;

        gettimeofday( &(st_cur->ftimer), NULL);

        for( i = 0; i < NB_PRB; i++ )
        {
            memset( st_cur->probes[i], 0, sizeof(
                    st_cur->probes[i] ) );
            st_cur->ssid_length[i] = 0;
        }

        G.st_end = st_cur;
    }

    if( st_cur->base == NULL ||
        memcmp( ap_cur->bssid, BROADCAST, 6 ) != 0 )
        st_cur->base = ap_cur;

    //update bitrate to station
    if( (st_cur != NULL) && ( h80211[1] & 3 ) == 2 )
        st_cur->rate_to = ri->ri_rate;

    /* update the last time seen */

    st_cur->tlast = time( NULL );

    /* only update power if packets comes from the
     * client: either type == Mgmt and SA != BSSID,
     * or FromDS == 0 and ToDS == 1 */

    if( ( ( h80211[1] & 3 ) == 0 &&
            memcmp( h80211 + 10, bssid, 6 ) != 0 ) ||
        ( ( h80211[1] & 3 ) == 1 ) )
    {
        st_cur->power = ri->ri_power;
        st_cur->rate_from = ri->ri_rate;
	if(ri->ri_channel > 0 && ri->ri_channel <= HIGHEST_CHANNEL)
		st_cur->channel = ri->ri_channel;
	else
		st_cur->channel = G.channel[cardnum];

        if(st_cur->lastseq != 0)
        {
            msd = seq - st_cur->lastseq - 1;
            if(msd > 0 && msd < 1000)
                st_cur->missed += msd;
        }
        st_cur->lastseq = seq;
    }

    st_cur->nb_pkt++;

skip_station:

    /* packet parsing: Probe Request */

    if( h80211[0] == 0x40 && st_cur != NULL )
    {
        p = h80211 + 24;

        while( p < h80211 + caplen )
        {
            if( p + 2 + p[1] > h80211 + caplen )
                break;

            if( p[0] == 0x00 && p[1] > 0 && p[2] != '\0' &&
                ( p[1] > 1 || p[2] != ' ' ) )
            {
//                n = ( p[1] > 32 ) ? 32 : p[1];
                n = p[1];

                for( i = 0; i < n; i++ )
                    if( p[2 + i] > 0 && p[2 + i] < ' ' )
                        goto skip_probe;

                /* got a valid ASCII probed ESSID, check if it's
                   already in the ring buffer */

                for( i = 0; i < NB_PRB; i++ )
                    if( memcmp( st_cur->probes[i], p + 2, n ) == 0 )
                        goto skip_probe;

                st_cur->probe_index = ( st_cur->probe_index + 1 ) % NB_PRB;
                memset( st_cur->probes[st_cur->probe_index], 0, 256 );
                memcpy( st_cur->probes[st_cur->probe_index], p + 2, n ); //twice?!
                st_cur->ssid_length[st_cur->probe_index] = n;

                for( i = 0; i < n; i++ )
                {
                    c = p[2 + i];
                    if( c == 0 || ( c > 126 && c < 160 ) ) c = '.';  //could also check ||(c>0 && c<32)
                    st_cur->probes[st_cur->probe_index][i] = c;
                }
            }

            p += 2 + p[1];
        }
    }

skip_probe:

    /* packet parsing: Beacon or Probe Response */

    if( h80211[0] == 0x80 || h80211[0] == 0x50 )
    {
        if( !(ap_cur->security & (STD_OPN|STD_WEP|STD_WPA|STD_WPA2)) )
        {
            if( ( h80211[34] & 0x10 ) >> 4 ) ap_cur->security |= STD_WEP|ENC_WEP;
            else ap_cur->security |= STD_OPN;
        }

        ap_cur->preamble = ( h80211[34] & 0x20 ) >> 5;

        unsigned long long *tstamp = (unsigned long long *) (h80211 + 24);
        ap_cur->timestamp = letoh64(*tstamp);

        p = h80211 + 36;

        while( p < h80211 + caplen )
        {
            if( p + 2 + p[1] > h80211 + caplen )
                break;

            //only update the essid length if the new length is > the old one
            if( p[0] == 0x00 && (ap_cur->ssid_length < p[1]) ) ap_cur->ssid_length = p[1];

            if( p[0] == 0x00 && p[1] > 0 && p[2] != '\0' &&
                ( p[1] > 1 || p[2] != ' ' ) )
            {
                /* found a non-cloaked ESSID */

//                n = ( p[1] > 32 ) ? 32 : p[1];
                n = p[1];

                memset( ap_cur->essid, 0, 256 );
                memcpy( ap_cur->essid, p + 2, n );

                if( G.f_ivs != NULL && !ap_cur->essid_stored )
                {
                    memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));
                    ivs2.flags |= IVS2_ESSID;
                    ivs2.len += ap_cur->ssid_length;

                    if( memcmp( G.prev_bssid, ap_cur->bssid, 6 ) != 0 )
                    {
                        ivs2.flags |= IVS2_BSSID;
                        ivs2.len += 6;
                        memcpy( G.prev_bssid, ap_cur->bssid,  6 );
                    }

                    /* write header */
                    if( fwrite( &ivs2, 1, sizeof(struct ivs2_pkthdr), G.f_ivs )
                        != (size_t) sizeof(struct ivs2_pkthdr) )
                    {
                        perror( "fwrite(IV header) failed" );
                        return( 1 );
                    }

                    /* write BSSID */
                    if(ivs2.flags & IVS2_BSSID)
                    {
                        if( fwrite( ap_cur->bssid, 1, 6, G.f_ivs )
                            != (size_t) 6 )
                        {
                            perror( "fwrite(IV bssid) failed" );
                            return( 1 );
                        }
                    }

                    /* write essid */
                    if( fwrite( ap_cur->essid, 1, ap_cur->ssid_length, G.f_ivs )
                        != (size_t) ap_cur->ssid_length )
                    {
                        perror( "fwrite(IV essid) failed" );
                        return( 1 );
                    }

                    ap_cur->essid_stored = 1;
                }

                for( i = 0; i < n; i++ )
                    if( ( ap_cur->essid[i] >   0 && ap_cur->essid[i] <  32 ) ||
                        ( ap_cur->essid[i] > 126 && ap_cur->essid[i] < 160 ) )
                        ap_cur->essid[i] = '.';
            }

            /* get the maximum speed in Mb and the AP's channel */

            if( p[0] == 0x01 || p[0] == 0x32 )
            {
                if(ap_cur->max_speed < ( p[1 + p[1]] & 0x7F ) / 2)
                    ap_cur->max_speed = ( p[1 + p[1]] & 0x7F ) / 2;
            }

            if( p[0] == 0x03 )
                ap_cur->channel = p[2];

            p += 2 + p[1];
        }
    }

    /* packet parsing: Beacon & Probe response */

    if( (h80211[0] == 0x80 || h80211[0] == 0x50) && caplen > 38)
    {
        p=h80211+36;         //ignore hdr + fixed params

        while( p < h80211 + caplen )
        {
            type = p[0];
            length = p[1];
            if(p+2+length > h80211 + caplen) {
/*                printf("error parsing tags! %p vs. %p (tag: %i, length: %i,position: %i)\n", (p+2+length), (h80211+caplen), type, length, (p-h80211));
                exit(1);*/
                break;
            }

            if( (type == 0xDD && (length >= 8) && (memcmp(p+2, "\x00\x50\xF2\x01\x01\x00", 6) == 0)) || (type == 0x30) )
            {
                ap_cur->security &= ~(STD_WEP|ENC_WEP|STD_WPA);

                org_p = p;
                offset = 0;

                if(type == 0xDD)
                {
                    //WPA defined in vendor specific tag -> WPA1 support
                    ap_cur->security |= STD_WPA;
                    offset = 4;
                }

                if(type == 0x30)
                {
                    ap_cur->security |= STD_WPA2;
                    offset = 0;
                }

                if(length < (18+offset))
                {
                    p += length+2;
                    continue;
                }

                if( p+9+offset > h80211+caplen )
                    break;
                numuni  = p[8+offset] + (p[9+offset]<<8);

                if( p+ (11+offset) + 4*numuni > h80211+caplen)
                    break;
                numauth = p[(10+offset) + 4*numuni] + (p[(11+offset) + 4*numuni]<<8);

                p += (10+offset);

                if(type != 0x30)
                {
                    if( p + (4*numuni) + (2+4*numauth) > h80211+caplen)
                        break;
                }
                else
                {
                    if( p + (4*numuni) + (2+4*numauth) + 2 > h80211+caplen)
                        break;
                }

                for(i=0; i<numuni; i++)
                {
                    switch(p[i*4+3])
                    {
                    case 0x01:
                        ap_cur->security |= ENC_WEP;
                        break;
                    case 0x02:
                        ap_cur->security |= ENC_TKIP;
                        break;
                    case 0x03:
                        ap_cur->security |= ENC_WRAP;
                        break;
                    case 0x04:
                        ap_cur->security |= ENC_CCMP;
                        break;
                    case 0x05:
                        ap_cur->security |= ENC_WEP104;
                        break;
                    default:
                        break;
                    }
                }

                p += 2+4*numuni;

                for(i=0; i<numauth; i++)
                {
                    switch(p[i*4+3])
                    {
                    case 0x01:
                        ap_cur->security |= AUTH_MGT;
                        break;
                    case 0x02:
                        ap_cur->security |= AUTH_PSK;
                        break;
                    default:
                        break;
                    }
                }

                p += 2+4*numauth;

                if( type == 0x30 ) p += 2;

                p = org_p + length+2;
            }
            else if( (type == 0xDD && (length >= 8) && (memcmp(p+2, "\x00\x50\xF2\x02\x01\x01", 6) == 0)))
            {
                ap_cur->security |= STD_QOS;
                p += length+2;
            }
            else if( (type == 0xDD && (length >= 4) && (memcmp(p+2, "\x00\x50\xF2\x04", 4) == 0)))
            {
                org_p = p;
                p+=6;
                int len = length, subtype = 0, sublen = 0;
                while(len >= 4)
                {
                    subtype = (p[0] << 8) + p[1];
                    sublen = (p[2] << 8) + p[3];
                    if(sublen > len)
                        break;
                    switch(subtype)
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
                    case 0x1054: // Primary Device Type
                        break;
                    case 0x1057: // AP Setup Locked
                        ap_cur->wps.ap_setup_locked = p[4];
                        break;
                    case 0x1008: // Config Methods
                    case 0x1053: // Selected Registrar Config Methods
                        ap_cur->wps.meth = (p[4] << 8) + p[5];
                        break;
                    default:     // Unknown type-length-value
                        break;
                    }
                    p += sublen+4;
                    len -= sublen+4;
                }
                p = org_p + length+2;
            }
            else p += length+2;
        }
    }

    /* packet parsing: Authentication Response */

    if( h80211[0] == 0xB0 && caplen >= 30)
    {
        if( ap_cur->security & STD_WEP )
        {
            //successful step 2 or 4 (coming from the AP)
            if(memcmp(h80211+28, "\x00\x00", 2) == 0 &&
                (h80211[26] == 0x02 || h80211[26] == 0x04))
            {
                ap_cur->security &= ~(AUTH_OPN | AUTH_PSK | AUTH_MGT);
                if(h80211[24] == 0x00) ap_cur->security |= AUTH_OPN;
                if(h80211[24] == 0x01) ap_cur->security |= AUTH_PSK;
            }
        }
    }

    /* packet parsing: Association Request */

    if( h80211[0] == 0x00 && caplen > 28 )
    {
        p = h80211 + 28;

        while( p < h80211 + caplen )
        {
            if( p + 2 + p[1] > h80211 + caplen )
                break;

            if( p[0] == 0x00 && p[1] > 0 && p[2] != '\0' &&
                ( p[1] > 1 || p[2] != ' ' ) )
            {
                /* found a non-cloaked ESSID */

                n = ( p[1] > 32 ) ? 32 : p[1];

                memset( ap_cur->essid, 0, 33 );
                memcpy( ap_cur->essid, p + 2, n );

                if( G.f_ivs != NULL && !ap_cur->essid_stored )
                {
                    memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));
                    ivs2.flags |= IVS2_ESSID;
                    ivs2.len += ap_cur->ssid_length;

                    if( memcmp( G.prev_bssid, ap_cur->bssid, 6 ) != 0 )
                    {
                        ivs2.flags |= IVS2_BSSID;
                        ivs2.len += 6;
                        memcpy( G.prev_bssid, ap_cur->bssid,  6 );
                    }

                    /* write header */
                    if( fwrite( &ivs2, 1, sizeof(struct ivs2_pkthdr), G.f_ivs )
                        != (size_t) sizeof(struct ivs2_pkthdr) )
                    {
                        perror( "fwrite(IV header) failed" );
                        return( 1 );
                    }

                    /* write BSSID */
                    if(ivs2.flags & IVS2_BSSID)
                    {
                        if( fwrite( ap_cur->bssid, 1, 6, G.f_ivs )
                            != (size_t) 6 )
                        {
                            perror( "fwrite(IV bssid) failed" );
                            return( 1 );
                        }
                    }

                    /* write essid */
                    if( fwrite( ap_cur->essid, 1, ap_cur->ssid_length, G.f_ivs )
                        != (size_t) ap_cur->ssid_length )
                    {
                        perror( "fwrite(IV essid) failed" );
                        return( 1 );
                    }

                    ap_cur->essid_stored = 1;
                }

                for( i = 0; i < n; i++ )
                    if( ap_cur->essid[i] < 32 ||
                      ( ap_cur->essid[i] > 126 && ap_cur->essid[i] < 160 ) )
                        ap_cur->essid[i] = '.';
            }

            p += 2 + p[1];
        }
        if(st_cur != NULL)
            st_cur->wpa.state = 0;
    }

    /* packet parsing: some data */

    if( ( h80211[0] & 0x0C ) == 0x08 )
    {
        /* update the channel if we didn't get any beacon */

        if( ap_cur->channel == -1 )
        {
            if(ri->ri_channel > 0 && ri->ri_channel <= HIGHEST_CHANNEL)
                ap_cur->channel = ri->ri_channel;
            else
                ap_cur->channel = G.channel[cardnum];
        }

        /* check the SNAP header to see if data is encrypted */

        z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;

        /* Check if 802.11e (QoS) */
        if( (h80211[0] & 0x80) == 0x80)
        {
            z+=2;
            if(st_cur != NULL)
            {
                if( (h80211[1] & 3) == 1 ) //ToDS
                    st_cur->qos_to_ds = 1;
                else
                    st_cur->qos_fr_ds = 1;
            }
        }
        else
        {
            if(st_cur != NULL)
            {
                if( (h80211[1] & 3) == 1 ) //ToDS
                    st_cur->qos_to_ds = 0;
                else
                    st_cur->qos_fr_ds = 0;
            }
        }

        if(z==24)
        {
            if(list_check_decloak(&(ap_cur->packets), caplen, h80211) != 0)
            {
                list_add_packet(&(ap_cur->packets), caplen, h80211);
            }
            else
            {
                ap_cur->is_decloak = 1;
                ap_cur->decloak_detect = 0;
                list_tail_free(&(ap_cur->packets));
                memset(G.message, '\x00', sizeof(G.message));
                    snprintf( G.message, sizeof( G.message ) - 1,
                        "][ Decloak: %02X:%02X:%02X:%02X:%02X:%02X ",
                        ap_cur->bssid[0], ap_cur->bssid[1], ap_cur->bssid[2],
                        ap_cur->bssid[3], ap_cur->bssid[4], ap_cur->bssid[5]);
            }
        }

        if( z + 26 > (unsigned)caplen )
            goto write_packet;

        if( h80211[z] == h80211[z + 1] && h80211[z + 2] == 0x03 )
        {
//            if( ap_cur->encryption < 0 )
//                ap_cur->encryption = 0;

            /* if ethertype == IPv4, find the LAN address */

            if( h80211[z + 6] == 0x08 && h80211[z + 7] == 0x00 &&
                ( h80211[1] & 3 ) == 0x01 )
                    memcpy( ap_cur->lanip, &h80211[z + 20], 4 );

            if( h80211[z + 6] == 0x08 && h80211[z + 7] == 0x06 )
                memcpy( ap_cur->lanip, &h80211[z + 22], 4 );
        }
//        else
//            ap_cur->encryption = 2 + ( ( h80211[z + 3] & 0x20 ) >> 5 );


        if(ap_cur->security == 0 || (ap_cur->security & STD_WEP) )
        {
            if( (h80211[1] & 0x40) != 0x40 )
            {
                ap_cur->security |= STD_OPN;
            }
            else
            {
                if((h80211[z+3] & 0x20) == 0x20)
                {
                    ap_cur->security |= STD_WPA;
                }
                else
                {
                    ap_cur->security |= STD_WEP;
                    if( (h80211[z+3] & 0xC0) != 0x00)
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

        if( z + 10 > (unsigned)caplen )
            goto write_packet;

        if( ap_cur->security & STD_WEP )
        {
            /* WEP: check if we've already seen this IV */

            if( ! uniqueiv_check( ap_cur->uiv_root, &h80211[z] ) )
            {
                /* first time seen IVs */

                if( G.f_ivs != NULL )
                {
                    memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));
                    ivs2.flags = 0;
                    ivs2.len = 0;

                    /* datalen = caplen - (header+iv+ivs) */
                    dlen = caplen -z -4 -4; //original data len
                    if(dlen > 2048) dlen = 2048;
                    //get cleartext + len + 4(iv+idx)
                    num_xor = known_clear(clear, &clen, weight, h80211, dlen);
                    if(num_xor == 1)
                    {
                        ivs2.flags |= IVS2_XOR;
                        ivs2.len += clen + 4;
                        /* reveal keystream (plain^encrypted) */
                        for(n=0; n<(ivs2.len-4); n++)
                        {
                            clear[n] = (clear[n] ^ h80211[z+4+n]) & 0xFF;
                        }
                        //clear is now the keystream
                    }
                    else
                    {
                        //do it again to get it 2 bytes higher
                        num_xor = known_clear(clear+2, &clen, weight, h80211, dlen);
                        ivs2.flags |= IVS2_PTW;
                        //len = 4(iv+idx) + 1(num of keystreams) + 1(len per keystream) + 32*num_xor + 16*sizeof(int)(weight[16])
                        ivs2.len += 4 + 1 + 1 + 32*num_xor + 16*sizeof(int);
                        clear[0] = num_xor;
                        clear[1] = clen;
                        /* reveal keystream (plain^encrypted) */
                        for(o=0; o<num_xor; o++)
                        {
                            for(n=0; n<(ivs2.len-4); n++)
                            {
                                clear[2+n+o*32] = (clear[2+n+o*32] ^ h80211[z+4+n]) & 0xFF;
                            }
                        }
                        memcpy(clear+4 + 1 + 1 + 32*num_xor, weight, 16*sizeof(int));
                        //clear is now the keystream
                    }

                    if( memcmp( G.prev_bssid, ap_cur->bssid, 6 ) != 0 )
                    {
                        ivs2.flags |= IVS2_BSSID;
                        ivs2.len += 6;
                        memcpy( G.prev_bssid, ap_cur->bssid,  6 );
                    }

                    if( fwrite( &ivs2, 1, sizeof(struct ivs2_pkthdr), G.f_ivs )
                        != (size_t) sizeof(struct ivs2_pkthdr) )
                    {
                        perror( "fwrite(IV header) failed" );
                        return( 1 );
                    }

                    if( ivs2.flags & IVS2_BSSID )
                    {
                        if( fwrite( ap_cur->bssid, 1, 6, G.f_ivs ) != (size_t) 6 )
                        {
                            perror( "fwrite(IV bssid) failed" );
                            return( 1 );
                        }
                        ivs2.len -= 6;
                    }

                    if( fwrite( h80211+z, 1, 4, G.f_ivs ) != (size_t) 4 )
                    {
                        perror( "fwrite(IV iv+idx) failed" );
                        return( 1 );
                    }
                    ivs2.len -= 4;

                    if( fwrite( clear, 1, ivs2.len, G.f_ivs ) != (size_t) ivs2.len )
                    {
                        perror( "fwrite(IV keystream) failed" );
                        return( 1 );
                    }
                }

                uniqueiv_mark( ap_cur->uiv_root, &h80211[z] );

                ap_cur->nb_data++;
            }

            // Record all data linked to IV to detect WEP Cloaking
            if( G.f_ivs == NULL && G.detect_anomaly)
            {
				// Only allocate this when seeing WEP AP
				if (ap_cur->data_root == NULL)
					ap_cur->data_root = data_init();

				// Only works with full capture, not IV-only captures
				if (data_check(ap_cur->data_root, &h80211[z], &h80211[z + 4])
					== CLOAKING && ap_cur->EAP_detected == 0)
				{

					//If no EAP/EAP was detected, indicate WEP cloaking
                    memset(G.message, '\x00', sizeof(G.message));
                    snprintf( G.message, sizeof( G.message ) - 1,
                        "][ WEP Cloaking: %02X:%02X:%02X:%02X:%02X:%02X ",
                        ap_cur->bssid[0], ap_cur->bssid[1], ap_cur->bssid[2],
                        ap_cur->bssid[3], ap_cur->bssid[4], ap_cur->bssid[5]);

				}
			}

        }
        else
        {
            ap_cur->nb_data++;
        }

        z = ( ( h80211[1] & 3 ) != 3 ) ? 24 : 30;

        /* Check if 802.11e (QoS) */
        if( (h80211[0] & 0x80) == 0x80) z+=2;

        if( z + 26 > (unsigned)caplen )
            goto write_packet;

        z += 6;     //skip LLC header

        /* check ethertype == EAPOL */
        if( h80211[z] == 0x88 && h80211[z + 1] == 0x8E && (h80211[1] & 0x40) != 0x40 )
        {
			ap_cur->EAP_detected = 1;

            z += 2;     //skip ethertype

            if( st_cur == NULL )
                goto write_packet;

            /* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */

            if( ( h80211[z + 6] & 0x08 ) != 0 &&
                  ( h80211[z + 6] & 0x40 ) == 0 &&
                  ( h80211[z + 6] & 0x80 ) != 0 &&
                  ( h80211[z + 5] & 0x01 ) == 0 )
            {
                memcpy( st_cur->wpa.anonce, &h80211[z + 17], 32 );
                st_cur->wpa.state = 1;
            }


            /* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */

            if( z+17+32 > (unsigned)caplen )
                goto write_packet;

            if( ( h80211[z + 6] & 0x08 ) != 0 &&
                  ( h80211[z + 6] & 0x40 ) == 0 &&
                  ( h80211[z + 6] & 0x80 ) == 0 &&
                  ( h80211[z + 5] & 0x01 ) != 0 )
            {
                if( memcmp( &h80211[z + 17], ZERO, 32 ) != 0 )
                {
                    memcpy( st_cur->wpa.snonce, &h80211[z + 17], 32 );
                    st_cur->wpa.state |= 2;

                }

                if( (st_cur->wpa.state & 4) != 4 )
                {
                    st_cur->wpa.eapol_size = ( h80211[z + 2] << 8 )
                            +   h80211[z + 3] + 4;

                    if (caplen - z < st_cur->wpa.eapol_size || st_cur->wpa.eapol_size == 0 ||
                        caplen - z < 81 + 16 || st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol))
                    {
                        // Ignore the packet trying to crash us.
                        st_cur->wpa.eapol_size = 0;
                        goto write_packet;
                    }

                    memcpy( st_cur->wpa.keymic, &h80211[z + 81], 16 );
                    memcpy( st_cur->wpa.eapol,  &h80211[z], st_cur->wpa.eapol_size );
                    memset( st_cur->wpa.eapol + 81, 0, 16 );
                    st_cur->wpa.state |= 4;
                    st_cur->wpa.keyver = h80211[z + 6] & 7;
                }
            }

            /* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */

            if( ( h80211[z + 6] & 0x08 ) != 0 &&
                  ( h80211[z + 6] & 0x40 ) != 0 &&
                  ( h80211[z + 6] & 0x80 ) != 0 &&
                  ( h80211[z + 5] & 0x01 ) != 0 )
            {
                if( memcmp( &h80211[z + 17], ZERO, 32 ) != 0 )
                {
                    memcpy( st_cur->wpa.anonce, &h80211[z + 17], 32 );
                    st_cur->wpa.state |= 1;
                }

                if( (st_cur->wpa.state & 4) != 4 )
                {
                    st_cur->wpa.eapol_size = ( h80211[z + 2] << 8 )
                            +   h80211[z + 3] + 4;

                    if (caplen - (unsigned)z < st_cur->wpa.eapol_size || st_cur->wpa.eapol_size == 0 ||
                        caplen - (unsigned)z < 81 + 16 || st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol))
                    {
                        // Ignore the packet trying to crash us.
                        st_cur->wpa.eapol_size = 0;
                        goto write_packet;
                    }

                    memcpy( st_cur->wpa.keymic, &h80211[z + 81], 16 );
                    memcpy( st_cur->wpa.eapol,  &h80211[z], st_cur->wpa.eapol_size );
                    memset( st_cur->wpa.eapol + 81, 0, 16 );
                    st_cur->wpa.state |= 4;
                    st_cur->wpa.keyver = h80211[z + 6] & 7;
                }
            }

            if( st_cur->wpa.state == 7)
            {
                memcpy( st_cur->wpa.stmac, st_cur->stmac, 6 );
                memcpy( G.wpa_bssid, ap_cur->bssid, 6 );
                memset(G.message, '\x00', sizeof(G.message));
                snprintf( G.message, sizeof( G.message ) - 1,
                    "][ WPA handshake: %02X:%02X:%02X:%02X:%02X:%02X ",
                    G.wpa_bssid[0], G.wpa_bssid[1], G.wpa_bssid[2],
                    G.wpa_bssid[3], G.wpa_bssid[4], G.wpa_bssid[5]);


                if( G.f_ivs != NULL )
                {
                    memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));
                    ivs2.flags = 0;
                    ivs2.len = 0;

                    ivs2.len= sizeof(struct WPA_hdsk);
                    ivs2.flags |= IVS2_WPA;

                    if( memcmp( G.prev_bssid, ap_cur->bssid, 6 ) != 0 )
                    {
                        ivs2.flags |= IVS2_BSSID;
                        ivs2.len += 6;
                        memcpy( G.prev_bssid, ap_cur->bssid,  6 );
                    }

                    if( fwrite( &ivs2, 1, sizeof(struct ivs2_pkthdr), G.f_ivs )
                        != (size_t) sizeof(struct ivs2_pkthdr) )
                    {
                        perror( "fwrite(IV header) failed" );
                        return( 1 );
                    }

                    if( ivs2.flags & IVS2_BSSID )
                    {
                        if( fwrite( ap_cur->bssid, 1, 6, G.f_ivs ) != (size_t) 6 )
                        {
                            perror( "fwrite(IV bssid) failed" );
                            return( 1 );
                        }
                        ivs2.len -= 6;
                    }

                    if( fwrite( &(st_cur->wpa), 1, sizeof(struct WPA_hdsk), G.f_ivs ) != (size_t) sizeof(struct WPA_hdsk) )
                    {
                        perror( "fwrite(IV wpa_hdsk) failed" );
                        return( 1 );
                    }
                }
            }
        }
    }


write_packet:

    if(ap_cur != NULL)
    {
        if( h80211[0] == 0x80 && G.one_beacon){
            if( !ap_cur->beacon_logged )
                ap_cur->beacon_logged = 1;
            else return ( 0 );
        }
    }

    if(G.record_data)
    {
        if( ( (h80211[0] & 0x0C) == 0x00 ) && ( (h80211[0] & 0xF0) == 0xB0 ) )
        {
            /* authentication packet */
            check_shared_key(h80211, caplen);
        }
    }

    if(ap_cur != NULL)
    {
        if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
        {
            return(1);
        }

        if(is_filtered_essid(ap_cur->essid))
        {
            return(1);
        }

    }

    /* this changes the local ap_cur, st_cur and na_cur variables and should be the last check befor the actual write */
    if(caplen < 24 && caplen >= 10 && h80211[0])
    {
        /* RTS || CTS || ACK || CF-END || CF-END&CF-ACK*/
        //(h80211[0] == 0xB4 || h80211[0] == 0xC4 || h80211[0] == 0xD4 || h80211[0] == 0xE4 || h80211[0] == 0xF4)

        /* use general control frame detection, as the structure is always the same: mac(s) starting at [4] */
        if(h80211[0] & 0x04)
        {
            p=h80211+4;
            while(p <= h80211+16 && p<=h80211+caplen)
            {
                memcpy(namac, p, 6);

                if(memcmp(namac, NULL_MAC, 6) == 0)
                {
                    p+=6;
                    continue;
                }

                if(memcmp(namac, BROADCAST, 6) == 0)
                {
                    p+=6;
                    continue;
                }

                if(G.hide_known)
                {
                    /* check AP list */
                    ap_cur = G.ap_1st;
                    ap_prv = NULL;

                    while( ap_cur != NULL )
                    {
                        if( ! memcmp( ap_cur->bssid, namac, 6 ) )
                            break;

                        ap_prv = ap_cur;
                        ap_cur = ap_cur->next;
                    }

                    /* if it's an AP, try next mac */

                    if( ap_cur != NULL )
                    {
                        p+=6;
                        continue;
                    }

                    /* check ST list */
                    st_cur = G.st_1st;
                    st_prv = NULL;

                    while( st_cur != NULL )
                    {
                        if( ! memcmp( st_cur->stmac, namac, 6 ) )
                            break;

                        st_prv = st_cur;
                        st_cur = st_cur->next;
                    }

                    /* if it's a client, try next mac */

                    if( st_cur != NULL )
                    {
                        p+=6;
                        continue;
                    }
                }

                /* not found in either AP list or ST list, look through NA list */
                na_cur = G.na_1st;
                na_prv = NULL;

                while( na_cur != NULL )
                {
                    if( ! memcmp( na_cur->namac, namac, 6 ) )
                        break;

                    na_prv = na_cur;
                    na_cur = na_cur->next;
                }

                /* update our chained list of unknown stations */
                /* if it's a new mac, add it */

                if( na_cur == NULL )
                {
                    if( ! ( na_cur = (struct NA_info *) malloc(
                                    sizeof( struct NA_info ) ) ) )
                    {
                        perror( "malloc failed" );
                        return( 1 );
                    }

                    memset( na_cur, 0, sizeof( struct NA_info ) );

                    if( G.na_1st == NULL )
                        G.na_1st = na_cur;
                    else
                        na_prv->next  = na_cur;

                    memcpy( na_cur->namac, namac, 6 );

                    na_cur->prev = na_prv;

                    gettimeofday(&(na_cur->tv), NULL);
                    na_cur->tinit = time( NULL );
                    na_cur->tlast = time( NULL );

                    na_cur->power   = -1;
                    na_cur->channel = -1;
                    na_cur->ack     = 0;
                    na_cur->ack_old = 0;
                    na_cur->ackps   = 0;
                    na_cur->cts     = 0;
                    na_cur->rts_r   = 0;
                    na_cur->rts_t   = 0;
                }

                /* update the last time seen & power*/

                na_cur->tlast = time( NULL );
                na_cur->power = ri->ri_power;
                na_cur->channel = ri->ri_channel;

                switch(h80211[0] & 0xF0)
                {
                    case 0xB0:
                        if(p == h80211+4)
                            na_cur->rts_r++;
                        if(p == h80211+10)
                            na_cur->rts_t++;
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
                p+=6;
            }
        }
    }

    if( G.f_cap != NULL && caplen >= 10)
    {
        pkh.caplen = pkh.len = caplen;

        gettimeofday( &tv, NULL );

        pkh.tv_sec  =   tv.tv_sec;
        pkh.tv_usec = ( tv.tv_usec & ~0x1ff ) + ri->ri_power + 64;

        n = sizeof( pkh );

        if( fwrite( &pkh, 1, n, G.f_cap ) != (size_t) n )
        {
            perror( "fwrite(packet header) failed" );
            return( 1 );
        }

        fflush( stdout );

        n = pkh.caplen;

        if( fwrite( h80211, 1, n, G.f_cap ) != (size_t) n )
        {
            perror( "fwrite(packet data) failed" );
            return( 1 );
        }

        fflush( stdout );
    }

    return( 0 );
}

void dump_sort( void )
{
    time_t tt = time( NULL );

    /* thanks to Arnaud Cornet :-) */

    struct AP_info *new_ap_1st = NULL;
    struct AP_info *new_ap_end = NULL;

    struct ST_info *new_st_1st = NULL;
    struct ST_info *new_st_end = NULL;

    struct ST_info *st_cur, *st_min;
    struct AP_info *ap_cur, *ap_min;

    /* sort the aps by WHATEVER first */

    while( G.ap_1st )
    {
        ap_min = NULL;
        ap_cur = G.ap_1st;

        while( ap_cur != NULL )
        {
            if( tt - ap_cur->tlast > 20 )
                ap_min = ap_cur;

            ap_cur = ap_cur->next;
        }

        if( ap_min == NULL )
        {
            ap_min = ap_cur = G.ap_1st;

/*#define SORT_BY_BSSID	1
#define SORT_BY_POWER	2
#define SORT_BY_BEACON	3
#define SORT_BY_DATA	4
#define SORT_BY_PRATE	6
#define SORT_BY_CHAN	7
#define	SORT_BY_MBIT	8
#define SORT_BY_ENC	9
#define SORT_BY_CIPHER	10
#define SORT_BY_AUTH	11
#define SORT_BY_ESSID	12*/

	    while( ap_cur != NULL )
            {
		switch (G.sort_by) {
		    case SORT_BY_BSSID:
			if( memcmp(ap_cur->bssid,ap_min->bssid,6)*G.sort_inv < 0)
			    ap_min = ap_cur;
			break;
		    case SORT_BY_POWER:
			if( (ap_cur->avg_power - ap_min->avg_power)*G.sort_inv < 0 )
			    ap_min = ap_cur;
			break;
		    case SORT_BY_BEACON:
			if( (ap_cur->nb_bcn < ap_min->nb_bcn)*G.sort_inv )
			    ap_min = ap_cur;
			break;
		    case SORT_BY_DATA:
			if( (ap_cur->nb_data < ap_min->nb_data)*G.sort_inv )
			    ap_min = ap_cur;
			break;
		    case SORT_BY_PRATE:
			if( (ap_cur->nb_dataps - ap_min->nb_dataps)*G.sort_inv < 0 )
			    ap_min = ap_cur;
			break;
		    case SORT_BY_CHAN:
			if( (ap_cur->channel - ap_min->channel)*G.sort_inv < 0 )
			    ap_min = ap_cur;
			break;
		    case SORT_BY_MBIT:
			if( (ap_cur->max_speed - ap_min->max_speed)*G.sort_inv < 0 )
			    ap_min = ap_cur;
			break;
		    case SORT_BY_ENC:
			if( ((ap_cur->security&STD_FIELD) - (ap_min->security&STD_FIELD))*G.sort_inv < 0 )
			    ap_min = ap_cur;
			break;
		    case SORT_BY_CIPHER:
			if( ((ap_cur->security&ENC_FIELD) - (ap_min->security&ENC_FIELD))*G.sort_inv < 0 )
			    ap_min = ap_cur;
			break;
		    case SORT_BY_AUTH:
			if( ((ap_cur->security&AUTH_FIELD) - (ap_min->security&AUTH_FIELD))*G.sort_inv < 0 )
			    ap_min = ap_cur;
			break;
		    case SORT_BY_ESSID:
			if( (strncasecmp((char*)ap_cur->essid, (char*)ap_min->essid, MAX_IE_ELEMENT_SIZE))*G.sort_inv < 0 )
			    ap_min = ap_cur;
			break;
		    default:	//sort by power
			if( ap_cur->avg_power < ap_min->avg_power)
			    ap_min = ap_cur;
			break;
		}
                ap_cur = ap_cur->next;
	    }
	}

        if( ap_min == G.ap_1st )
            G.ap_1st = ap_min->next;

        if( ap_min == G.ap_end )
            G.ap_end = ap_min->prev;

        if( ap_min->next )
            ap_min->next->prev = ap_min->prev;

        if( ap_min->prev )
            ap_min->prev->next = ap_min->next;

        if( new_ap_end )
        {
            new_ap_end->next = ap_min;
            ap_min->prev = new_ap_end;
            new_ap_end = ap_min;
            new_ap_end->next = NULL;
        }
        else
        {
            new_ap_1st = new_ap_end = ap_min;
            ap_min->next = ap_min->prev = NULL;
        }
    }

    G.ap_1st = new_ap_1st;
    G.ap_end = new_ap_end;

    /* now sort the stations */

    while( G.st_1st )
    {
        st_min = NULL;
        st_cur = G.st_1st;

        while( st_cur != NULL )
        {
            if( tt - st_cur->tlast > 60 )
                st_min = st_cur;

            st_cur = st_cur->next;
        }

        if( st_min == NULL )
        {
            st_min = st_cur = G.st_1st;

            while( st_cur != NULL )
            {
                if( st_cur->power < st_min->power)
                    st_min = st_cur;

                st_cur = st_cur->next;
            }
        }

        if( st_min == G.st_1st )
            G.st_1st = st_min->next;

        if( st_min == G.st_end )
            G.st_end = st_min->prev;

        if( st_min->next )
            st_min->next->prev = st_min->prev;

        if( st_min->prev )
            st_min->prev->next = st_min->next;

        if( new_st_end )
        {
            new_st_end->next = st_min;
            st_min->prev = new_st_end;
            new_st_end = st_min;
            new_st_end->next = NULL;
        }
        else
        {
            new_st_1st = new_st_end = st_min;
            st_min->next = st_min->prev = NULL;
        }
    }

    G.st_1st = new_st_1st;
    G.st_end = new_st_end;
}

int getBatteryState()
{
	return get_battery_state();
}

char * getStringTimeFromSec(double seconds)
{
    int hour[3];
    char * ret;
    char * HourTime;
    char * MinTime;

    if (seconds <0)
        return NULL;

    ret = (char *) calloc(1,256);

    HourTime = (char *) calloc (1,128);
    MinTime  = (char *) calloc (1,128);

    hour[0]  = (int) (seconds);
    hour[1]  = hour[0] / 60;
    hour[2]  = hour[1] / 60;
    hour[0] %= 60 ;
    hour[1] %= 60 ;

    if (hour[2] != 0 )
        snprintf(HourTime, 128, "%d %s", hour[2], ( hour[2] == 1 ) ? "hour" : "hours");
    if (hour[1] != 0 )
        snprintf(MinTime, 128, "%d %s", hour[1], ( hour[1] == 1 ) ? "min" : "mins");

    if ( hour[2] != 0 && hour[1] != 0 )
        snprintf(ret, 256, "%s %s", HourTime, MinTime);
    else
    {
        if (hour[2] == 0 && hour[1] == 0)
            snprintf(ret, 256, "%d s", hour[0] );
        else
            snprintf(ret, 256, "%s", (hour[2] == 0) ? MinTime : HourTime );
    }

    free(MinTime);
    free(HourTime);

    return ret;

}

char * getBatteryString(void)
{
    int batt_time;
    char * ret;
    char * batt_string;

    batt_time = getBatteryState();

    if ( batt_time <= 60 ) {
        ret = (char *) calloc(1,2);
        ret[0] = ']';
        return ret;
    }

    batt_string = getStringTimeFromSec( (double) batt_time );

    ret = (char *) calloc( 1, 256 );

    snprintf( ret, 256, "][ BAT: %s ]", batt_string );

    free( batt_string);

    return ret;
}

int get_ap_list_count() {
    time_t tt;
    struct tm *lt;
    struct AP_info *ap_cur;

    int num_ap;

    tt = time( NULL );
    lt = localtime( &tt );

    ap_cur = G.ap_end;

    num_ap = 0;

    while( ap_cur != NULL )
    {
        /* skip APs with only one packet, or those older than 2 min.
         * always skip if bssid == broadcast */

        if( ap_cur->nb_pkt < 2 || time( NULL ) - ap_cur->tlast > G.berlin ||
            memcmp( ap_cur->bssid, BROADCAST, 6 ) == 0 )
        {
            ap_cur = ap_cur->prev;
            continue;
        }

        if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
        {
            ap_cur = ap_cur->prev;
            continue;
        }

        if(is_filtered_essid(ap_cur->essid))
        {
            ap_cur = ap_cur->prev;
            continue;
        }

	num_ap++;
	ap_cur = ap_cur->prev;
    }

    return num_ap;
}

int get_sta_list_count() {
    time_t tt;
    struct tm *lt;
    struct AP_info *ap_cur;
    struct ST_info *st_cur;

    int num_sta;

    tt = time( NULL );
    lt = localtime( &tt );

    ap_cur = G.ap_end;

    num_sta = 0;

    while( ap_cur != NULL )
    {
        if( ap_cur->nb_pkt < 2 ||
            time( NULL ) - ap_cur->tlast > G.berlin )
        {
            ap_cur = ap_cur->prev;
            continue;
        }

        if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
        {
            ap_cur = ap_cur->prev;
            continue;
        }

        // Don't filter unassociated clients by ESSID
        if(memcmp(ap_cur->bssid, BROADCAST, 6) && is_filtered_essid(ap_cur->essid))
        {
            ap_cur = ap_cur->prev;
            continue;
        }

        st_cur = G.st_end;

        while( st_cur != NULL )
        {
            if( st_cur->base != ap_cur ||
                time( NULL ) - st_cur->tlast > G.berlin )
            {
                st_cur = st_cur->prev;
                continue;
            }

            if( ! memcmp( ap_cur->bssid, BROADCAST, 6 ) && G.asso_client )
            {
                st_cur = st_cur->prev;
                continue;
            }

	    num_sta++;

            st_cur = st_cur->prev;
        }

        ap_cur = ap_cur->prev;
    }
    return num_sta;
}

#define TSTP_SEC 1000000ULL /* It's a 1 MHz clock, so a million ticks per second! */
#define TSTP_MIN (TSTP_SEC * 60ULL)
#define TSTP_HOUR (TSTP_MIN * 60ULL)
#define TSTP_DAY (TSTP_HOUR * 24ULL)

static char *parse_timestamp(unsigned long long timestamp) {
	static char s[15];
	unsigned long long rem;
	unsigned int days, hours, mins, secs;

	days = timestamp / TSTP_DAY;
	rem = timestamp % TSTP_DAY;
	hours = rem / TSTP_HOUR;
	rem %= TSTP_HOUR;
	mins = rem / TSTP_MIN;
	rem %= TSTP_MIN;
	secs = rem / TSTP_SEC;

	snprintf(s, 14, "%3dd %02d:%02d:%02d", days, hours, mins, secs);

	return s;
}

void dump_print( int ws_row, int ws_col, int if_num )
{
    time_t tt;
    struct tm *lt;
    int nlines, i, n, len;
    char strbuf[512];
    char buffer[512];
    char ssid_list[512];
    struct AP_info *ap_cur;
    struct ST_info *st_cur;
    struct NA_info *na_cur;
    int columns_ap = 83;
    int columns_sta = 74;
    int columns_na = 68;

    int num_ap;
    int num_sta;

    if(!G.singlechan) columns_ap -= 4; //no RXQ in scan mode
    if(G.show_uptime) columns_ap += 15; //show uptime needs more space

    nlines = 2;

    if( nlines >= ws_row )
        return;

    if(G.do_sort_always) {
	pthread_mutex_lock( &(G.mx_sort) );
	    dump_sort();
	pthread_mutex_unlock( &(G.mx_sort) );
    }

    tt = time( NULL );
    lt = localtime( &tt );

    if(G.is_berlin)
    {
        G.maxaps = 0;
        G.numaps = 0;
        ap_cur = G.ap_end;

        while( ap_cur != NULL )
        {
            G.maxaps++;
            if( ap_cur->nb_pkt < 2 || time( NULL ) - ap_cur->tlast > G.berlin ||
                memcmp( ap_cur->bssid, BROADCAST, 6 ) == 0 )
            {
                ap_cur = ap_cur->prev;
                continue;
            }
            G.numaps++;
            ap_cur = ap_cur->prev;
        }

        if(G.numaps > G.maxnumaps)
            G.maxnumaps = G.numaps;

//        G.maxaps--;
    }

    /*
     *  display the channel, battery, position (if we are connected to GPSd)
     *  and current time
     */

    memset( strbuf, '\0', sizeof(strbuf) );
    strbuf[ws_col - 1] = '\0';
    fprintf( stderr, "%s\n", strbuf );

    if(G.freqoption)
    {
        snprintf(strbuf, sizeof(strbuf)-1, " Freq %4d", G.frequency[0]);
        for(i=1; i<if_num; i++)
        {
            memset( buffer, '\0', sizeof(buffer) );
            snprintf(buffer, sizeof(buffer) , ",%4d", G.frequency[i]);
            strncat(strbuf, buffer, sizeof(strbuf) - strlen(strbuf) - 1);
        }
    }
    else
    {
        snprintf(strbuf, sizeof(strbuf)-1, " CH %2d", G.channel[0]);
        for(i=1; i<if_num; i++)
        {
            memset( buffer, '\0', sizeof(buffer) );
            snprintf(buffer, sizeof(buffer) , ",%2d", G.channel[i]);
            strncat(strbuf, buffer, sizeof(strbuf) - strlen(strbuf) -1);
        }
    }
    memset( buffer, '\0', sizeof(buffer) );

    if (G.gps_loc[0]) {
        snprintf( buffer, sizeof( buffer ) - 1,
              " %s[ GPS %8.3f %8.3f %8.3f %6.2f "
              "][ Elapsed: %s ][ %04d-%02d-%02d %02d:%02d ", G.batt,
              G.gps_loc[0], G.gps_loc[1], G.gps_loc[2], G.gps_loc[3],
              G.elapsed_time , 1900 + lt->tm_year,
              1 + lt->tm_mon, lt->tm_mday, lt->tm_hour, lt->tm_min );
    }
    else
    {
        snprintf( buffer, sizeof( buffer ) - 1,
              " %s[ Elapsed: %s ][ %04d-%02d-%02d %02d:%02d ",
              G.batt, G.elapsed_time, 1900 + lt->tm_year,
              1 + lt->tm_mon, lt->tm_mday, lt->tm_hour, lt->tm_min );
    }

    strncat(strbuf, buffer, (512-strlen(strbuf)));
    memset( buffer, '\0', 512 );

    if(G.is_berlin)
    {
        snprintf( buffer, sizeof( buffer ) - 1,
              " ][%3d/%3d/%4d ",
              G.numaps, G.maxnumaps, G.maxaps);
    }

    strncat(strbuf, buffer, (512-strlen(strbuf)));
    memset( buffer, '\0', 512 );

    if(strlen(G.message) > 0)
    {
        strncat(strbuf, G.message, (512-strlen(strbuf)));
    }

    //add traling spaces to overwrite previous messages
    strncat(strbuf, "                                        ", (512-strlen(strbuf)));

    strbuf[ws_col - 1] = '\0';
    fprintf( stderr, "%s\n", strbuf );

    /* print some informations about each detected AP */

    nlines += 3;

    if( nlines >= ws_row )
        return;

    memset( strbuf, ' ', ws_col - 1 );
    strbuf[ws_col - 1] = '\0';
    fprintf( stderr, "%s\n", strbuf );

    if(G.show_ap) {

    strbuf[0] = 0;
    strcat(strbuf, " BSSID              PWR ");

    if(G.singlechan)
    	strcat(strbuf, "RXQ ");

    strcat(strbuf, " Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ");

    if (G.show_uptime)
    	strcat(strbuf, "       UPTIME  ");

    if (G.show_wps)
    {
        strcat(strbuf, "WPS   ");
        if ( ws_col > (columns_ap - 4) )
        {
            memset(strbuf+columns_ap, 32, G.maxsize_wps_seen - 6 );
            snprintf(strbuf+columns_ap+G.maxsize_wps_seen-6, 9,"%s","   ESSID");
            if ( G.show_manufacturer  )
            {
                memset(strbuf+columns_ap+G.maxsize_wps_seen+2, 32, G.maxsize_essid_seen-5 );
                snprintf(strbuf+columns_ap+G.maxsize_essid_seen-5, 15,"%s","  MANUFACTURER");
            }
        }
    }
    else
    {
    strcat(strbuf, "ESSID");

	if ( G.show_manufacturer && ( ws_col > (columns_ap - 4) ) ) {
		// write spaces (32).
		memset(strbuf+columns_ap, 32, G.maxsize_essid_seen - 5 ); // 5 is the len of "ESSID"
		snprintf(strbuf+columns_ap+G.maxsize_essid_seen-5, 15,"%s","  MANUFACTURER");
	}
    }
	strbuf[ws_col - 1] = '\0';
	fprintf( stderr, "%s\n", strbuf );

	memset( strbuf, ' ', ws_col - 1 );
	strbuf[ws_col - 1] = '\0';
	fprintf( stderr, "%s\n", strbuf );

	ap_cur = G.ap_end;

	if(G.selection_ap) {
	    num_ap = get_ap_list_count();
	    if(G.selected_ap > num_ap)
		G.selected_ap = num_ap;
	}

	if(G.selection_sta) {
	    num_sta = get_sta_list_count();
	    if(G.selected_sta > num_sta)
		G.selected_sta = num_sta;
	}

	num_ap = 0;

	if(G.selection_ap) {
	    G.start_print_ap = G.selected_ap - ((ws_row-1) - nlines) + 1;
	    if(G.start_print_ap < 1)
		G.start_print_ap = 1;
    //	printf("%i\n", G.start_print_ap);
	}


	while( ap_cur != NULL )
	{
	    /* skip APs with only one packet, or those older than 2 min.
	    * always skip if bssid == broadcast */

	    if( ap_cur->nb_pkt < 2 || time( NULL ) - ap_cur->tlast > G.berlin ||
		memcmp( ap_cur->bssid, BROADCAST, 6 ) == 0 )
	    {
		ap_cur = ap_cur->prev;
		continue;
	    }

	    if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
	    {
		ap_cur = ap_cur->prev;
		continue;
	    }

	    if(is_filtered_essid(ap_cur->essid))
	    {
		ap_cur = ap_cur->prev;
		continue;
	    }

	    num_ap++;

	    if(num_ap < G.start_print_ap) {
		ap_cur = ap_cur->prev;
		continue;
	    }

	    nlines++;

	    if( nlines > (ws_row-1) )
		return;

	    memset(strbuf, '\0', sizeof(strbuf));

	    snprintf( strbuf, sizeof(strbuf), " %02X:%02X:%02X:%02X:%02X:%02X",
		    ap_cur->bssid[0], ap_cur->bssid[1],
		    ap_cur->bssid[2], ap_cur->bssid[3],
		    ap_cur->bssid[4], ap_cur->bssid[5] );

	    len = strlen(strbuf);

	    if(G.singlechan)
	    {
		snprintf( strbuf+len, sizeof(strbuf)-len, "  %3d %3d %8ld %8ld %4d",
			ap_cur->avg_power,
			ap_cur->rx_quality,
			ap_cur->nb_bcn,
			ap_cur->nb_data,
			ap_cur->nb_dataps );
	    }
	    else
	    {
		snprintf( strbuf+len, sizeof(strbuf)-len, "  %3d %8ld %8ld %4d",
			ap_cur->avg_power,
			ap_cur->nb_bcn,
			ap_cur->nb_data,
			ap_cur->nb_dataps );
	    }

	    len = strlen(strbuf);

	    snprintf( strbuf+len, sizeof(strbuf)-len, " %3d %3d%c%c ",
		    ap_cur->channel, ap_cur->max_speed,
		    ( ap_cur->security & STD_QOS ) ? 'e' : ' ',
		    ( ap_cur->preamble ) ? '.' : ' ');

	    len = strlen(strbuf);

	    if( (ap_cur->security & (STD_OPN|STD_WEP|STD_WPA|STD_WPA2)) == 0) snprintf( strbuf+len, sizeof(strbuf)-len, "    " );
	    else if( ap_cur->security & STD_WPA2 ) snprintf( strbuf+len, sizeof(strbuf)-len, "WPA2" );
	    else if( ap_cur->security & STD_WPA  ) snprintf( strbuf+len, sizeof(strbuf)-len, "WPA " );
	    else if( ap_cur->security & STD_WEP  ) snprintf( strbuf+len, sizeof(strbuf)-len, "WEP " );
	    else if( ap_cur->security & STD_OPN  ) snprintf( strbuf+len, sizeof(strbuf)-len, "OPN " );

	    strncat( strbuf, " ", sizeof(strbuf) - strlen(strbuf) - 1);

	    len = strlen(strbuf);

	    if( (ap_cur->security & (ENC_WEP|ENC_TKIP|ENC_WRAP|ENC_CCMP|ENC_WEP104|ENC_WEP40)) == 0 ) snprintf( strbuf+len, sizeof(strbuf)-len, "       ");
	    else if( ap_cur->security & ENC_CCMP   ) snprintf( strbuf+len, sizeof(strbuf)-len, "CCMP   ");
	    else if( ap_cur->security & ENC_WRAP   ) snprintf( strbuf+len, sizeof(strbuf)-len, "WRAP   ");
	    else if( ap_cur->security & ENC_TKIP   ) snprintf( strbuf+len, sizeof(strbuf)-len, "TKIP   ");
	    else if( ap_cur->security & ENC_WEP104 ) snprintf( strbuf+len, sizeof(strbuf)-len, "WEP104 ");
	    else if( ap_cur->security & ENC_WEP40  ) snprintf( strbuf+len, sizeof(strbuf)-len, "WEP40  ");
	    else if( ap_cur->security & ENC_WEP    ) snprintf( strbuf+len, sizeof(strbuf)-len, "WEP    ");

	    len = strlen(strbuf);

	    if( (ap_cur->security & (AUTH_OPN|AUTH_PSK|AUTH_MGT)) == 0 ) snprintf( strbuf+len, sizeof(strbuf)-len, "   ");
	    else if( ap_cur->security & AUTH_MGT   ) snprintf( strbuf+len, sizeof(strbuf)-len, "MGT");
	    else if( ap_cur->security & AUTH_PSK   )
	    {
		if( ap_cur->security & STD_WEP )
		    snprintf( strbuf+len, sizeof(strbuf)-len, "SKA");
		else
		    snprintf( strbuf+len, sizeof(strbuf)-len, "PSK");
	    }
	    else if( ap_cur->security & AUTH_OPN   ) snprintf( strbuf+len, sizeof(strbuf)-len, "OPN");

	    len = strlen(strbuf);

	    if (G.show_uptime) {
	    	snprintf(strbuf+len, sizeof(strbuf)-len, " %14s", parse_timestamp(ap_cur->timestamp));
	    	len = strlen(strbuf);
	    }

	    strbuf[ws_col-1] = '\0';

	    if(G.selection_ap && ((num_ap) == G.selected_ap)) {
		if(G.mark_cur_ap) {
		    if(ap_cur->marked == 0) {
			ap_cur->marked = 1;
		    }
		    else {
			ap_cur->marked_color++;
			if(ap_cur->marked_color > (TEXT_MAX_COLOR-1)) {
			    ap_cur->marked_color = 1;
			    ap_cur->marked = 0;
			}
		    }
		    G.mark_cur_ap = 0;
		}
		textstyle(TEXT_REVERSE);
		memcpy(G.selected_bssid, ap_cur->bssid, 6);
	    }

	    if(ap_cur->marked) {
		textcolor_fg(ap_cur->marked_color);
	    }

	    fprintf(stderr, "%s", strbuf);

	    if( ws_col > (columns_ap - 4) )
	    {
		memset( strbuf, 0, sizeof( strbuf ) );
		if (G.show_wps)
		{
		    if (ap_cur->wps.state != 0xFF)
		    {
		        if (ap_cur->wps.ap_setup_locked) // AP setup locked
		            snprintf(strbuf, sizeof(strbuf)-1, "Locked");
		        else
		        {
		            snprintf(strbuf, sizeof(strbuf)-1, "%d.%d", ap_cur->wps.version >> 4, ap_cur->wps.version & 0xF); // Version
		            if (ap_cur->wps.meth) // WPS Config Methods
		            {
		                char tbuf[64];
		                memset( tbuf, '\0', sizeof(tbuf) );
		                int sep = 0;
#define T(bit, name) do {                       \
    if (ap_cur->wps.meth & (1<<bit)) {          \
        if (sep)                                \
            strcat(tbuf, ",");                  \
        sep = 1;                                \
        strncat(tbuf, name, (64-strlen(tbuf))); \
    } } while (0)
		                T(0, "USB");     // USB method
		                T(1, "ETHER");   // Ethernet
		                T(2, "LAB");     // Label
		                T(3, "DISP");    // Display
		                T(4, "EXTNFC");  // Ext. NFC Token
		                T(5, "INTNFC");  // Int. NFC Token
		                T(6, "NFCINTF"); // NFC Interface
		                T(7, "PBC");     // Push Button
		                T(8, "KPAD");    // Keypad
		                snprintf(strbuf+strlen(strbuf), sizeof(strbuf)-strlen(strbuf), " %s", tbuf);
#undef T
		            }
		        }
		    }
		    else
		        snprintf(strbuf, sizeof(strbuf)-1, " ");

			if (G.maxsize_wps_seen <= strlen(strbuf))
				G.maxsize_wps_seen = strlen(strbuf);
			else // write spaces (32)
				memset( strbuf+strlen(strbuf), 32,  (G.maxsize_wps_seen - strlen(strbuf))  );
		}
		if(ap_cur->essid[0] != 0x00)
		{
		    if (G.show_wps)
		    snprintf( strbuf + G.maxsize_wps_seen, sizeof(strbuf)-G.maxsize_wps_seen,
			    "  %s", ap_cur->essid );
		    else
		    snprintf( strbuf,  sizeof( strbuf ) - 1,
			    "%s", ap_cur->essid );
		}
		else
		{
		    if (G.show_wps)
		    snprintf( strbuf + G.maxsize_wps_seen, sizeof(strbuf)-G.maxsize_wps_seen,
			    "  <length:%3d>%s", ap_cur->ssid_length, "\x00" );
		    else
		    snprintf( strbuf,  sizeof( strbuf ) - 1,
			    "<length:%3d>%s", ap_cur->ssid_length, "\x00" );
		}

		if (G.show_manufacturer) {

			if (G.maxsize_essid_seen <= strlen(strbuf))
				G.maxsize_essid_seen = strlen(strbuf);
			else // write spaces (32)
				memset( strbuf+strlen(strbuf), 32,  (G.maxsize_essid_seen - strlen(strbuf))  );

			if (ap_cur->manuf == NULL)
				ap_cur->manuf = get_manufacturer(ap_cur->bssid[0], ap_cur->bssid[1], ap_cur->bssid[2]);

			snprintf( strbuf + G.maxsize_essid_seen , sizeof(strbuf)-G.maxsize_essid_seen, "  %s", ap_cur->manuf );
		}

		// write spaces (32) until the end of column
		memset( strbuf+strlen(strbuf), 32, ws_col - (columns_ap - 4 ) );

		// end the string at the end of the column
		strbuf[ws_col - (columns_ap - 4)] = '\0';

		fprintf( stderr, "  %s", strbuf );
	    }

	    fprintf( stderr, "\n" );

	    if( (G.selection_ap && ((num_ap) == G.selected_ap)) || (ap_cur->marked) ) {
		textstyle(TEXT_RESET);
	    }

	    ap_cur = ap_cur->prev;
	}

	/* print some informations about each detected station */

	nlines += 3;

	if( nlines >= (ws_row-1) )
	    return;

	memset( strbuf, ' ', ws_col - 1 );
	strbuf[ws_col - 1] = '\0';
	fprintf( stderr, "%s\n", strbuf );
    }

    if(G.show_sta) {
	memcpy( strbuf, " BSSID              STATION "
		"           PWR   Rate    Lost    Frames  Probes", columns_sta );
	strbuf[ws_col - 1] = '\0';
	fprintf( stderr, "%s\n", strbuf );

	memset( strbuf, ' ', ws_col - 1 );
	strbuf[ws_col - 1] = '\0';
	fprintf( stderr, "%s\n", strbuf );

	ap_cur = G.ap_end;

	num_sta = 0;

	while( ap_cur != NULL )
	{
	    if( ap_cur->nb_pkt < 2 ||
		time( NULL ) - ap_cur->tlast > G.berlin )
	    {
		ap_cur = ap_cur->prev;
		continue;
	    }

	    if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
	    {
		ap_cur = ap_cur->prev;
		continue;
	    }

	    // Don't filter unassociated clients by ESSID
	    if(memcmp(ap_cur->bssid, BROADCAST, 6) && is_filtered_essid(ap_cur->essid))
	    {
		ap_cur = ap_cur->prev;
		continue;
	    }

	    if( nlines >= (ws_row-1) )
		return;

	    st_cur = G.st_end;

	    if(G.selection_ap && (memcmp(G.selected_bssid, ap_cur->bssid, 6)==0)) {
		textstyle(TEXT_REVERSE);
	    }

	    if(ap_cur->marked) {
		textcolor_fg(ap_cur->marked_color);
	    }

	    while( st_cur != NULL )
	    {
		if( st_cur->base != ap_cur ||
		    time( NULL ) - st_cur->tlast > G.berlin )
		{
		    st_cur = st_cur->prev;
		    continue;
		}

		if( ! memcmp( ap_cur->bssid, BROADCAST, 6 ) && G.asso_client )
		{
		    st_cur = st_cur->prev;
		    continue;
		}

		num_sta++;

		if(G.start_print_sta > num_sta)
		    continue;

		nlines++;

		if( ws_row != 0 && nlines >= ws_row )
		    return;

		if( ! memcmp( ap_cur->bssid, BROADCAST, 6 ) )
		    fprintf( stderr, " (not associated) " );
		else
		    fprintf( stderr, " %02X:%02X:%02X:%02X:%02X:%02X",
			    ap_cur->bssid[0], ap_cur->bssid[1],
			    ap_cur->bssid[2], ap_cur->bssid[3],
			    ap_cur->bssid[4], ap_cur->bssid[5] );

		fprintf( stderr, "  %02X:%02X:%02X:%02X:%02X:%02X",
			st_cur->stmac[0], st_cur->stmac[1],
			st_cur->stmac[2], st_cur->stmac[3],
			st_cur->stmac[4], st_cur->stmac[5] );

		fprintf( stderr, "  %3d ", st_cur->power    );
		fprintf( stderr, "  %2d", st_cur->rate_to/1000000  );
		fprintf( stderr,  "%c", (st_cur->qos_fr_ds) ? 'e' : ' ');
		fprintf( stderr,  "-%2d", st_cur->rate_from/1000000);
		fprintf( stderr,  "%c", (st_cur->qos_to_ds) ? 'e' : ' ');
		fprintf( stderr, "  %4d", st_cur->missed   );
		fprintf( stderr, " %8ld", st_cur->nb_pkt   );

		if( ws_col > (columns_sta - 6) )
		{
		    memset( ssid_list, 0, sizeof( ssid_list ) );

		    for( i = 0, n = 0; i < NB_PRB; i++ )
		    {
			if( st_cur->probes[i][0] == '\0' )
			    continue;

			snprintf( ssid_list + n, sizeof( ssid_list ) - n - 1,
				"%c%s", ( i > 0 ) ? ',' : ' ',
				st_cur->probes[i] );

			n += ( 1 + strlen( st_cur->probes[i] ) );

			if( n >= (int) sizeof( ssid_list ) )
			    break;
		    }

		    memset( strbuf, 0, sizeof( strbuf ) );
		    snprintf( strbuf,  sizeof( strbuf ) - 1,
			    "%-256s", ssid_list );
		    strbuf[ws_col - (columns_sta - 6)] = '\0';
		    fprintf( stderr, " %s", strbuf );
		}

		fprintf( stderr, "\n" );

		st_cur = st_cur->prev;
	    }

	    if( (G.selection_ap && (memcmp(G.selected_bssid, ap_cur->bssid, 6)==0)) || (ap_cur->marked) ) {
		textstyle(TEXT_RESET);
	    }

	    ap_cur = ap_cur->prev;
	}
    }

    if(G.show_ack)
    {
        /* print some informations about each unknown station */

        nlines += 3;

        if( nlines >= (ws_row-1) )
            return;

        memset( strbuf, ' ', ws_col - 1 );
        strbuf[ws_col - 1] = '\0';
        fprintf( stderr, "%s\n", strbuf );

        memcpy( strbuf, " MAC       "
                "          CH PWR    ACK ACK/s    CTS RTS_RX RTS_TX  OTHER", columns_na );
        strbuf[ws_col - 1] = '\0';
        fprintf( stderr, "%s\n", strbuf );

        memset( strbuf, ' ', ws_col - 1 );
        strbuf[ws_col - 1] = '\0';
        fprintf( stderr, "%s\n", strbuf );

        na_cur = G.na_1st;

        while( na_cur != NULL )
        {
            if( time( NULL ) - na_cur->tlast > 120 )
            {
                na_cur = na_cur->next;
                continue;
            }

            if( nlines >= (ws_row-1) )
                return;

            nlines++;

            if( ws_row != 0 && nlines >= ws_row )
                return;

            fprintf( stderr, " %02X:%02X:%02X:%02X:%02X:%02X",
                    na_cur->namac[0], na_cur->namac[1],
                    na_cur->namac[2], na_cur->namac[3],
                    na_cur->namac[4], na_cur->namac[5] );

            fprintf( stderr, "  %3d", na_cur->channel  );
            fprintf( stderr, " %3d", na_cur->power  );
            fprintf( stderr, " %6d", na_cur->ack );
            fprintf( stderr, "  %4d", na_cur->ackps );
            fprintf( stderr, " %6d", na_cur->cts );
            fprintf( stderr, " %6d", na_cur->rts_r );
            fprintf( stderr, " %6d", na_cur->rts_t );
            fprintf( stderr, " %6d", na_cur->other );

            fprintf( stderr, "\n" );

            na_cur = na_cur->next;
        }
    }
}

char * format_text_for_csv( const unsigned char * input, int len)
{
	// Unix style encoding
	char * ret;
	int i, pos, contains_space_end;
	const char * hex_table = "0123456789ABCDEF";

	if (len < 0)
	{
		return NULL;
	}

	if (len == 0 || input == NULL)
	{
		ret = (char*)malloc(1);
		ret[0] = 0;
		return ret;
	}

	pos = 0;
	contains_space_end = (input[0] == ' ') || input[len-1] == ' ';

	// Make sure to have enough memory for all that stuff
	ret = (char *)malloc((len*4)+1+2);

	if (contains_space_end)
	{
		ret[pos++] = '"';
	}

	for (i=0; i < len; i++)
	{
		if (!isprint(input[i]) || input[i] == ',' || input[i] == '\\' || input[i] == '"')
		{
			ret[pos++] = '\\';
		}

		if (isprint(input[i]))
		{
			ret[pos++] = input[i];
		}
		else if (input[i] == '\n' || input[i] == '\r' || input[i] == '\t')
		{
			ret[pos++] = (input[i] == '\n') ? 'n' : (input[i] == '\t') ? 't' : 'r';
		}
		else
		{
			ret[pos++] = 'x';
			ret[pos++] = hex_table[input[i]/16];
			ret[pos++] = hex_table[input[i]%16];
		}
	}

	if (contains_space_end)
	{
		ret[pos++] = '"';
	}

	ret[pos++] = '\0';

	ret = realloc(ret, pos);

	return ret;
}

int dump_write_csv( void )
{
    int i, n, probes_written;
    struct tm *ltime;
    struct AP_info *ap_cur;
    struct ST_info *st_cur;
    char * temp;

    if (! G.record_data || !G.output_format_csv)
    	return 0;

    fseek( G.f_txt, 0, SEEK_SET );

    fprintf( G.f_txt,
        "\r\nBSSID, First time seen, Last time seen, channel, Speed, "
        "Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\r\n" );

    ap_cur = G.ap_1st;

    while( ap_cur != NULL )
    {
        if( memcmp( ap_cur->bssid, BROADCAST, 6 ) == 0 )
        {
            ap_cur = ap_cur->next;
            continue;
        }

        if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
        {
            ap_cur = ap_cur->next;
            continue;
        }

        if(is_filtered_essid(ap_cur->essid))
        {
            ap_cur = ap_cur->next;
            continue;
        }

        fprintf( G.f_txt, "%02X:%02X:%02X:%02X:%02X:%02X, ",
                 ap_cur->bssid[0], ap_cur->bssid[1],
                 ap_cur->bssid[2], ap_cur->bssid[3],
                 ap_cur->bssid[4], ap_cur->bssid[5] );

        ltime = localtime( &ap_cur->tinit );

        fprintf( G.f_txt, "%04d-%02d-%02d %02d:%02d:%02d, ",
                 1900 + ltime->tm_year, 1 + ltime->tm_mon,
                 ltime->tm_mday, ltime->tm_hour,
                 ltime->tm_min,  ltime->tm_sec );

        ltime = localtime( &ap_cur->tlast );

        fprintf( G.f_txt, "%04d-%02d-%02d %02d:%02d:%02d, ",
                 1900 + ltime->tm_year, 1 + ltime->tm_mon,
                 ltime->tm_mday, ltime->tm_hour,
                 ltime->tm_min,  ltime->tm_sec );

        fprintf( G.f_txt, "%2d, %3d,",
                 ap_cur->channel,
                 ap_cur->max_speed );

        if( (ap_cur->security & (STD_OPN|STD_WEP|STD_WPA|STD_WPA2)) == 0) fprintf( G.f_txt, " " );
        else
        {
            if( ap_cur->security & STD_WPA2 ) fprintf( G.f_txt, " WPA2" );
            if( ap_cur->security & STD_WPA  ) fprintf( G.f_txt, " WPA" );
            if( ap_cur->security & STD_WEP  ) fprintf( G.f_txt, " WEP" );
            if( ap_cur->security & STD_OPN  ) fprintf( G.f_txt, " OPN" );
        }

        fprintf( G.f_txt, ",");

        if( (ap_cur->security & (ENC_WEP|ENC_TKIP|ENC_WRAP|ENC_CCMP|ENC_WEP104|ENC_WEP40)) == 0 ) fprintf( G.f_txt, " ");
        else
        {
            if( ap_cur->security & ENC_CCMP   ) fprintf( G.f_txt, " CCMP");
            if( ap_cur->security & ENC_WRAP   ) fprintf( G.f_txt, " WRAP");
            if( ap_cur->security & ENC_TKIP   ) fprintf( G.f_txt, " TKIP");
            if( ap_cur->security & ENC_WEP104 ) fprintf( G.f_txt, " WEP104");
            if( ap_cur->security & ENC_WEP40  ) fprintf( G.f_txt, " WEP40");
            if( ap_cur->security & ENC_WEP    ) fprintf( G.f_txt, " WEP");
        }

        fprintf( G.f_txt, ",");

        if( (ap_cur->security & (AUTH_OPN|AUTH_PSK|AUTH_MGT)) == 0 ) fprintf( G.f_txt, "   ");
        else
        {
            if( ap_cur->security & AUTH_MGT   ) fprintf( G.f_txt, " MGT");
            if( ap_cur->security & AUTH_PSK   )
			{
				if( ap_cur->security & STD_WEP )
					fprintf( G.f_txt, "SKA");
				else
					fprintf( G.f_txt, "PSK");
			}
            if( ap_cur->security & AUTH_OPN   ) fprintf( G.f_txt, " OPN");
        }

        fprintf( G.f_txt, ", %3d, %8ld, %8ld, ",
                 ap_cur->avg_power,
                 ap_cur->nb_bcn,
                 ap_cur->nb_data );

        fprintf( G.f_txt, "%3d.%3d.%3d.%3d, ",
                 ap_cur->lanip[0], ap_cur->lanip[1],
                 ap_cur->lanip[2], ap_cur->lanip[3] );

        fprintf( G.f_txt, "%3d, ", ap_cur->ssid_length);

	temp = format_text_for_csv(ap_cur->essid, ap_cur->ssid_length);
        fprintf( G.f_txt, "%s, ", temp );
	free(temp);

        if(ap_cur->key != NULL)
        {
            for(i=0; i<(int)strlen(ap_cur->key); i++)
            {
                fprintf( G.f_txt, "%02X", ap_cur->key[i]);
                if(i<(int)(strlen(ap_cur->key)-1))
                    fprintf( G.f_txt, ":");
            }
        }

        fprintf( G.f_txt, "\r\n");

        ap_cur = ap_cur->next;
    }

    fprintf( G.f_txt,
        "\r\nStation MAC, First time seen, Last time seen, "
        "Power, # packets, BSSID, Probed ESSIDs\r\n" );

    st_cur = G.st_1st;

    while( st_cur != NULL )
    {
        ap_cur = st_cur->base;

        if( ap_cur->nb_pkt < 2 )
        {
            st_cur = st_cur->next;
            continue;
        }

        fprintf( G.f_txt, "%02X:%02X:%02X:%02X:%02X:%02X, ",
                 st_cur->stmac[0], st_cur->stmac[1],
                 st_cur->stmac[2], st_cur->stmac[3],
                 st_cur->stmac[4], st_cur->stmac[5] );

        ltime = localtime( &st_cur->tinit );

        fprintf( G.f_txt, "%04d-%02d-%02d %02d:%02d:%02d, ",
                 1900 + ltime->tm_year, 1 + ltime->tm_mon,
                 ltime->tm_mday, ltime->tm_hour,
                 ltime->tm_min,  ltime->tm_sec );

        ltime = localtime( &st_cur->tlast );

        fprintf( G.f_txt, "%04d-%02d-%02d %02d:%02d:%02d, ",
                 1900 + ltime->tm_year, 1 + ltime->tm_mon,
                 ltime->tm_mday, ltime->tm_hour,
                 ltime->tm_min,  ltime->tm_sec );

        fprintf( G.f_txt, "%3d, %8ld, ",
                 st_cur->power,
                 st_cur->nb_pkt );

        if( ! memcmp( ap_cur->bssid, BROADCAST, 6 ) )
            fprintf( G.f_txt, "(not associated) ," );
        else
            fprintf( G.f_txt, "%02X:%02X:%02X:%02X:%02X:%02X,",
                     ap_cur->bssid[0], ap_cur->bssid[1],
                     ap_cur->bssid[2], ap_cur->bssid[3],
                     ap_cur->bssid[4], ap_cur->bssid[5] );

	

	probes_written = 0;
        for( i = 0, n = 0; i < NB_PRB; i++ )
        {
            if( st_cur->ssid_length[i] == 0 )
                continue;

	    temp = format_text_for_csv(st_cur->probes[i], st_cur->ssid_length[i]);

	    if( probes_written == 0)
	    {
		fprintf( G.f_txt, "%s", temp);
		probes_written = 1;
	    }
	    else
	    {
		fprintf( G.f_txt, ",%s", temp);
	    }

	    free(temp);
        }

        fprintf( G.f_txt, "\r\n" );

        st_cur = st_cur->next;
    }

    fprintf( G.f_txt, "\r\n" );
    fflush( G.f_txt );
    return 0;
}

char * sanitize_xml(unsigned char * text, int length)
{
	int i;
	size_t len, current_text_len;
	unsigned char * pos;
	char * newtext = NULL;
	if (text != NULL && length > 0) {
		len = 8 * length;
		newtext = (char *)calloc(1, (len + 1) * sizeof(char)); // Make sure we have enough space
		pos = text;
		for (i = 0; i < length; ++i, ++pos) {
			switch (*pos) {
				case '&':
					strncat(newtext, "&amp;", len);
					break;
				case '<':
					strncat(newtext, "&lt;", len);
					break;
				case '>':
					strncat(newtext, "&gt;", len);
					break;
				case '\'':
					strncat(newtext, "&apos;", len);
					break;
				case '"':
					strncat(newtext, "&quot;", len);
					break;
				case '\r':
					strncat(newtext, "&#xD;", len);
					break;
				case '\n':
					strncat(newtext, "&#xA;", len);
					break;
				default:
					if ( isprint((int)(*pos)) ) {
						newtext[strlen(newtext)] = *pos;
					} else {
						strncat(newtext, "&#x", len);
						current_text_len = strlen(newtext);
						snprintf(newtext + current_text_len, len - current_text_len + 1, "%4x", *pos);
						strncat(newtext, ";", len);
					}
					break;
			}
		}
		newtext = (char *) realloc(newtext, strlen(newtext) + 1);
	}

	return newtext;
}


#define OUI_STR_SIZE 8
#define MANUF_SIZE 128
char *get_manufacturer(unsigned char mac0, unsigned char mac1, unsigned char mac2) {
	char oui[OUI_STR_SIZE + 1];
	char *manuf;
	//char *buffer_manuf;
	char * manuf_str;
	struct oui *ptr;
	FILE *fp;
	char buffer[BUFSIZ];
	char temp[OUI_STR_SIZE + 1];
	unsigned char a[2];
	unsigned char b[2];
	unsigned char c[2];
	int found = 0;

	if ((manuf = (char *)calloc(1, MANUF_SIZE * sizeof(char))) == NULL) {
		perror("calloc failed");
		return NULL;
	}

	snprintf(oui, sizeof(oui), "%02X:%02X:%02X", mac0, mac1, mac2 );

	if (G.manufList != NULL) {
		// Search in the list
		ptr = G.manufList;
		while (ptr != NULL) {
			found = ! strncasecmp(ptr->id, oui, OUI_STR_SIZE);
			if (found) {
				memcpy(manuf, ptr->manuf, MANUF_SIZE);
				break;
			}
			ptr = ptr->next;
		}
	} else {
		// If the file exist, then query it each time we need to get a manufacturer.
		fp = open_oui_file();

		if (fp != NULL) {

			memset(buffer, 0x00, sizeof(buffer));
			while (fgets(buffer, sizeof(buffer), fp) != NULL) {
				if (strstr(buffer, "(hex)") == NULL) {
					continue;
				}

				memset(a, 0x00, sizeof(a));
				memset(b, 0x00, sizeof(b));
				memset(c, 0x00, sizeof(c));
				if (sscanf(buffer, "%2c-%2c-%2c", a, b, c) == 3) {
					snprintf(temp, sizeof(temp), "%c%c:%c%c:%c%c", a[0], a[1], b[0], b[1], c[0], c[1] );
					found = !memcmp(temp, oui, strlen(oui));
					if (found) {
						manuf_str = get_manufacturer_from_string(buffer);
						if (manuf_str != NULL) {
							snprintf(manuf, MANUF_SIZE, "%s", manuf_str);
							free(manuf_str);
						}

						break;
					}
				}
				memset(buffer, 0x00, sizeof(buffer));
			}

			fclose(fp);
		}
	}

	// Not found, use "Unknown".
	if (!found || *manuf == '\0') {
		memcpy(manuf, "Unknown", 7);
		manuf[strlen(manuf)] = '\0';
	}

	manuf = (char *)realloc(manuf, (strlen(manuf) + 1) * sizeof(char));

	return manuf;
}
#undef OUI_STR_SIZE
#undef MANUF_SIZE


#define KISMET_NETXML_HEADER_BEGIN "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<!DOCTYPE detection-run SYSTEM \"http://kismetwireless.net/kismet-3.1.0.dtd\">\n\n<detection-run kismet-version=\"airodump-ng-1.0\" start-time=\""
#define KISMET_NETXML_HEADER_END "\">\n\n"

#define KISMET_NETXML_TRAILER "</detection-run>"

#define TIME_STR_LENGTH 255
int dump_write_kismet_netxml_client_info(struct ST_info *client, int client_no)
{
	char first_time[TIME_STR_LENGTH];
	char last_time[TIME_STR_LENGTH];
	char * manuf;
	int client_max_rate, average_power, i, nb_probes_written, is_unassociated;
	char * essid = NULL;

	if (client == NULL || client_no < 1) {
		return 1;
	}

	is_unassociated = (client->base == NULL || memcmp(client->base->bssid, BROADCAST, 6) == 0);

	strncpy(first_time, ctime(&client->tinit), TIME_STR_LENGTH - 1);
	first_time[strlen(first_time) - 1] = 0; // remove new line

	strncpy(last_time, ctime(&client->tlast), TIME_STR_LENGTH - 1);
	last_time[strlen(last_time) - 1] = 0; // remove new line

	fprintf(G.f_kis_xml, "\t\t<wireless-client number=\"%d\" "
				 "type=\"%s\" first-time=\"%s\""
				 " last-time=\"%s\">\n",
				 client_no, (is_unassociated) ? "tods" : "established",
				 first_time, last_time );

	fprintf( G.f_kis_xml, "\t\t\t<client-mac>%02X:%02X:%02X:%02X:%02X:%02X</client-mac>\n",
				 client->stmac[0], client->stmac[1],
				 client->stmac[2], client->stmac[3],
				 client->stmac[4], client->stmac[5] );

	/* Manufacturer, if set using standard oui list */
	manuf = sanitize_xml((unsigned char *)client->manuf, strlen(client->manuf));
	fprintf(G.f_kis_xml, "\t\t\t<client-manuf>%s</client-manuf>\n", (manuf != NULL) ? manuf : "Unknown");
	free(manuf);

	/* SSID item, aka Probes */
	nb_probes_written = 0;
	for( i = 0; i < NB_PRB; i++ )
        {
		if( client->probes[i][0] == '\0' )
			continue;

		fprintf( G.f_kis_xml, "\t\t\t<SSID first-time=\"%s\" last-time=\"%s\">\n",
					first_time, last_time);
		fprintf( G.f_kis_xml, "\t\t\t\t<type>Probe Request</type>\n"
					"\t\t\t\t<max-rate>54.000000</max-rate>\n"
					"\t\t\t\t<packets>1</packets>\n"
					"\t\t\t\t<encryption>None</encryption>\n");
		essid = sanitize_xml(client->probes[i], client->ssid_length[i]);
		if (essid != NULL) {
			fprintf( G.f_kis_xml, "\t\t\t\t<ssid>%s</ssid>\n", essid);
			free(essid);
		}
		
		fprintf( G.f_kis_xml, "\t\t\t</SSID>\n");

		++nb_probes_written;
        }

	// Unassociated client with broadcast probes
	if (is_unassociated && nb_probes_written == 0)
	{
		fprintf( G.f_kis_xml, "\t\t\t<SSID first-time=\"%s\" last-time=\"%s\">\n",
					first_time, last_time);
		fprintf( G.f_kis_xml, "\t\t\t\t<type>Probe Request</type>\n"
					"\t\t\t\t<max-rate>54.000000</max-rate>\n"
					"\t\t\t\t<packets>1</packets>\n"
					"\t\t\t\t<encryption>None</encryption>\n");
		fprintf( G.f_kis_xml, "\t\t\t</SSID>\n");
	}

	/* Channel
	   FIXME: Take G.freqoption in account */
	fprintf(G.f_kis_xml, "\t\t\t<channel>%d</channel>\n", client->channel);

	/* Rate: inaccurate because it's the latest rate seen */
	client_max_rate = ( client->rate_from > client->rate_to ) ? client->rate_from : client->rate_to ;
	fprintf(G.f_kis_xml, "\t\t\t<maxseenrate>%.6f</maxseenrate>\n", client_max_rate / 1000000.0 );

	/* Those 2 lines always stays the same */
	fprintf(G.f_kis_xml, "\t\t\t<carrier>IEEE 802.11b+</carrier>\n");
	fprintf(G.f_kis_xml, "\t\t\t<encoding>CCK</encoding>\n");

	/* Packets */
	fprintf(G.f_kis_xml, "\t\t\t<packets>\n"
				"\t\t\t\t<LLC>0</LLC>\n"
				"\t\t\t\t<data>0</data>\n"
				"\t\t\t\t<crypt>0</crypt>\n"
				"\t\t\t\t<total>%ld</total>\n"
				"\t\t\t\t<fragments>0</fragments>\n"
				"\t\t\t\t<retries>0</retries>\n"
				"\t\t\t</packets>\n",
				client->nb_pkt );

	/* SNR information */
	average_power = (client->power == -1) ? 0 : client->power;
	fprintf(G.f_kis_xml, "\t\t\t<snr-info>\n"
			"\t\t\t\t<last_signal_dbm>%d</last_signal_dbm>\n"
			"\t\t\t\t<last_noise_dbm>0</last_noise_dbm>\n"
			"\t\t\t\t<last_signal_rssi>%d</last_signal_rssi>\n"
			"\t\t\t\t<last_noise_rssi>0</last_noise_rssi>\n"
			"\t\t\t\t<min_signal_dbm>%d</min_signal_dbm>\n"
			"\t\t\t\t<min_noise_dbm>0</min_noise_dbm>\n"
			"\t\t\t\t<min_signal_rssi>1024</min_signal_rssi>\n"
			"\t\t\t\t<min_noise_rssi>1024</min_noise_rssi>\n"
			"\t\t\t\t<max_signal_dbm>%d</max_signal_dbm>\n"
			"\t\t\t\t<max_noise_dbm>0</max_noise_dbm>\n"
			"\t\t\t\t<max_signal_rssi>%d</max_signal_rssi>\n"
			"\t\t\t\t<max_noise_rssi>0</max_noise_rssi>\n"
			 "\t\t\t</snr-info>\n",
			 average_power, average_power, average_power,
			 average_power, average_power );

	/* GPS Coordinates
	   XXX: We don't have GPS coordinates for clients */
	if (G.usegpsd)
	{
		fprintf(G.f_kis_xml, "\t\t\t<gps-info>\n"
					"\t\t\t\t<min-lat>%.6f</min-lat>\n"
					"\t\t\t\t<min-lon>%.6f</min-lon>\n"
					"\t\t\t\t<min-alt>%.6f</min-alt>\n"
					"\t\t\t\t<min-spd>%.6f</min-spd>\n"
					"\t\t\t\t<max-lat>%.6f</max-lat>\n"
					"\t\t\t\t<max-lon>%.6f</max-lon>\n"
					"\t\t\t\t<max-alt>%.6f</max-alt>\n"
					"\t\t\t\t<max-spd>%.6f</max-spd>\n"
					"\t\t\t\t<peak-lat>%.6f</peak-lat>\n"
					"\t\t\t\t<peak-lon>%.6f</peak-lon>\n"
					"\t\t\t\t<peak-alt>%.6f</peak-alt>\n"
					"\t\t\t\t<avg-lat>%.6f</avg-lat>\n"
					"\t\t\t\t<avg-lon>%.6f</avg-lon>\n"
					"\t\t\t\t<avg-alt>%.6f</avg-alt>\n"
					 "\t\t\t</gps-info>\n",
					 0.0, 0.0, 0.0, 0.0,
					 0.0, 0.0, 0.0, 0.0,
					 0.0, 0.0, 0.0,
					 0.0, 0.0, 0.0 );
	}
	fprintf(G.f_kis_xml, "\t\t</wireless-client>\n" );

	return 0;
}

#define NETXML_ENCRYPTION_TAG "%s<encryption>%s</encryption>\n"
int dump_write_kismet_netxml( void )
{
    int network_number, average_power, client_max_rate, max_power, client_nbr, unused;
    struct AP_info *ap_cur;
    struct ST_info *st_cur;
    char first_time[TIME_STR_LENGTH];
    char last_time[TIME_STR_LENGTH];
    char * manuf;
    char * essid = NULL;

    if (! G.record_data || !G.output_format_kismet_netxml)
    	return 0;

    fseek( G.f_kis_xml, 0, SEEK_SET );

	/* Header and airodump-ng start time */
    fprintf( G.f_kis_xml, "%s%s%s",
    		KISMET_NETXML_HEADER_BEGIN,
			G.airodump_start_time,
    		KISMET_NETXML_HEADER_END );


    ap_cur = G.ap_1st;

    network_number = 0;
    while( ap_cur != NULL )
    {
        if( memcmp( ap_cur->bssid, BROADCAST, 6 ) == 0 )
        {
            ap_cur = ap_cur->next;
            continue;
        }

        if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
        {
            ap_cur = ap_cur->next;
            continue;
        }

        if(is_filtered_essid(ap_cur->essid))
        {
            ap_cur = ap_cur->next;
            continue;
        }

		++network_number; // Network Number
		strncpy(first_time, ctime(&ap_cur->tinit), TIME_STR_LENGTH - 1);
		first_time[strlen(first_time) - 1] = 0; // remove new line

		strncpy(last_time, ctime(&ap_cur->tlast), TIME_STR_LENGTH - 1);
		last_time[strlen(last_time) - 1] = 0; // remove new line

		fprintf(G.f_kis_xml, "\t<wireless-network number=\"%d\" type=\"infrastructure\" ",
			network_number);
		fprintf(G.f_kis_xml, "first-time=\"%s\" last-time=\"%s\">\n", first_time, last_time);

		fprintf(G.f_kis_xml, "\t\t<SSID first-time=\"%s\" last-time=\"%s\">\n",
				first_time, last_time);
		fprintf(G.f_kis_xml, "\t\t\t<type>Beacon</type>\n" );
		fprintf(G.f_kis_xml, "\t\t\t<max-rate>%d.000000</max-rate>\n", ap_cur->max_speed );
		fprintf(G.f_kis_xml, "\t\t\t<packets>%ld</packets>\n", ap_cur->nb_bcn );
		fprintf(G.f_kis_xml, "\t\t\t<beaconrate>%d</beaconrate>\n", 10 );

		// Encryption
		if( ap_cur->security & STD_OPN  ) fprintf( G.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "None" );
		else if( ap_cur->security & STD_WEP  ) fprintf( G.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WEP" );
		else if( ap_cur->security & STD_WPA2 || ap_cur->security & STD_WPA  )
		{
			if( ap_cur->security & ENC_TKIP   ) fprintf( G.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WPA+TKIP" );
			if( ap_cur->security & AUTH_MGT   ) fprintf( G.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WPA+MGT" ); // Not a valid value: NetXML does not have a value for WPA Enterprise
			if( ap_cur->security & AUTH_PSK   ) fprintf( G.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WPA+PSK" );
			if( ap_cur->security & ENC_CCMP   ) fprintf( G.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WPA+AES-CCM" );
			if( ap_cur->security & ENC_WRAP   ) fprintf( G.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WPA+AES-OCB" );
		}
		else if( ap_cur->security & ENC_WEP104 ) fprintf( G.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WEP104" );
		else if( ap_cur->security & ENC_WEP40  ) fprintf( G.f_kis_xml, NETXML_ENCRYPTION_TAG, "\t\t\t", "WEP40" );

		/* ESSID */
		fprintf(G.f_kis_xml, "\t\t\t<essid cloaked=\"%s\">",
					(ap_cur->essid[0] == 0) ? "true" : "false");
		essid = sanitize_xml(ap_cur->essid, ap_cur->ssid_length);
		if (essid != NULL) {
			fprintf(G.f_kis_xml, "%s", essid);
			free(essid);
		}
		fprintf(G.f_kis_xml, "</essid>\n");

		/* End of SSID tag */
		fprintf(G.f_kis_xml, "\t\t</SSID>\n");

		/* BSSID */
		fprintf( G.f_kis_xml, "\t\t<BSSID>%02X:%02X:%02X:%02X:%02X:%02X</BSSID>\n",
					 ap_cur->bssid[0], ap_cur->bssid[1],
					 ap_cur->bssid[2], ap_cur->bssid[3],
					 ap_cur->bssid[4], ap_cur->bssid[5] );

		/* Manufacturer, if set using standard oui list */
		manuf = sanitize_xml((unsigned char *)ap_cur->manuf, strlen(ap_cur->manuf));
		fprintf(G.f_kis_xml, "\t\t<manuf>%s</manuf>\n", (manuf != NULL) ? manuf : "Unknown");
		free(manuf);

		/* Channel
		   FIXME: Take G.freqoption in account */
		fprintf(G.f_kis_xml, "\t\t<channel>%d</channel>\n", (ap_cur->channel) == -1 ? 0 : ap_cur->channel);

		/* Freq (in Mhz) and total number of packet on that frequency
		   FIXME: Take G.freqoption in account */
		fprintf(G.f_kis_xml, "\t\t<freqmhz>%d %ld</freqmhz>\n",
					(ap_cur->channel) == -1 ? 0 : getFrequencyFromChannel(ap_cur->channel),
					//ap_cur->nb_data + ap_cur->nb_bcn );
					ap_cur->nb_pkt );

		/* XXX: What about 5.5Mbit */
		fprintf(G.f_kis_xml, "\t\t<maxseenrate>%d</maxseenrate>\n", (ap_cur->max_speed == -1) ? 0 : ap_cur->max_speed * 1000);

		/* Those 2 lines always stays the same */
		fprintf(G.f_kis_xml, "\t\t<carrier>IEEE 802.11b+</carrier>\n");
		fprintf(G.f_kis_xml, "\t\t<encoding>CCK</encoding>\n");

		/* Packets */
		fprintf(G.f_kis_xml, "\t\t<packets>\n"
					"\t\t\t<LLC>%ld</LLC>\n"
					"\t\t\t<data>%ld</data>\n"
					"\t\t\t<crypt>0</crypt>\n"
					"\t\t\t<total>%ld</total>\n"
					"\t\t\t<fragments>0</fragments>\n"
					"\t\t\t<retries>0</retries>\n"
					"\t\t</packets>\n",
					ap_cur->nb_data, ap_cur->nb_data,
					//ap_cur->nb_data + ap_cur->nb_bcn );
					ap_cur->nb_pkt );


		/* XXX: What does that field mean? Is it the total size of data? */
		fprintf(G.f_kis_xml, "\t\t<datasize>0</datasize>\n");

		/* Client information */
		st_cur = G.st_1st;
		client_nbr = 0;

		while ( st_cur != NULL )
		{
			/* Check if the station is associated to the current AP */
			if ( memcmp( st_cur->stmac, BROADCAST, 6 ) != 0 &&
				st_cur->base != NULL &&
				memcmp( st_cur->base->bssid, ap_cur->bssid, 6 ) == 0 )
			{
				dump_write_kismet_netxml_client_info(st_cur, ++client_nbr);
			}

			/* Next client */
			st_cur = st_cur->next;
		}

		/* SNR information */
		average_power = (ap_cur->avg_power == -1) ? 0 : ap_cur->avg_power;
		max_power = (ap_cur->best_power == -1) ? average_power : ap_cur->best_power;
		fprintf(G.f_kis_xml, "\t\t<snr-info>\n"
					"\t\t\t<last_signal_dbm>%d</last_signal_dbm>\n"
					"\t\t\t<last_noise_dbm>0</last_noise_dbm>\n"
					"\t\t\t<last_signal_rssi>%d</last_signal_rssi>\n"
					"\t\t\t<last_noise_rssi>0</last_noise_rssi>\n"
					"\t\t\t<min_signal_dbm>%d</min_signal_dbm>\n"
					"\t\t\t<min_noise_dbm>0</min_noise_dbm>\n"
					"\t\t\t<min_signal_rssi>1024</min_signal_rssi>\n"
					"\t\t\t<min_noise_rssi>1024</min_noise_rssi>\n"
					"\t\t\t<max_signal_dbm>%d</max_signal_dbm>\n"
					"\t\t\t<max_noise_dbm>0</max_noise_dbm>\n"
					"\t\t\t<max_signal_rssi>%d</max_signal_rssi>\n"
					"\t\t\t<max_noise_rssi>0</max_noise_rssi>\n"
					 "\t\t</snr-info>\n",
					 average_power, average_power, average_power,
					 max_power, max_power );

		/* GPS Coordinates */
		if (G.usegpsd)
		{
			fprintf(G.f_kis_xml, "\t\t<gps-info>\n"
						"\t\t\t<min-lat>%.6f</min-lat>\n"
						"\t\t\t<min-lon>%.6f</min-lon>\n"
						"\t\t\t<min-alt>%.6f</min-alt>\n"
						"\t\t\t<min-spd>%.6f</min-spd>\n"
						"\t\t\t<max-lat>%.6f</max-lat>\n"
						"\t\t\t<max-lon>%.6f</max-lon>\n"
						"\t\t\t<max-alt>%.6f</max-alt>\n"
						"\t\t\t<max-spd>%.6f</max-spd>\n"
						"\t\t\t<peak-lat>%.6f</peak-lat>\n"
						"\t\t\t<peak-lon>%.6f</peak-lon>\n"
						"\t\t\t<peak-alt>%.6f</peak-alt>\n"
						"\t\t\t<avg-lat>%.6f</avg-lat>\n"
						"\t\t\t<avg-lon>%.6f</avg-lon>\n"
						"\t\t\t<avg-alt>%.6f</avg-alt>\n"
						 "\t\t</gps-info>\n",
						ap_cur->gps_loc_min[0],
						ap_cur->gps_loc_min[1],
						ap_cur->gps_loc_min[2],
						ap_cur->gps_loc_min[3],
						ap_cur->gps_loc_max[0],
						ap_cur->gps_loc_max[1],
						ap_cur->gps_loc_max[2],
						ap_cur->gps_loc_max[3],
						ap_cur->gps_loc_best[0],
						ap_cur->gps_loc_best[1],
						ap_cur->gps_loc_best[2],
						/* Can the "best" be considered as average??? */
						ap_cur->gps_loc_best[0],
						ap_cur->gps_loc_best[1],
						ap_cur->gps_loc_best[2] );
		}

		/* BSS Timestamp */
		fprintf(G.f_kis_xml, "\t\t<bsstimestamp>%llu</bsstimestamp>\n", ap_cur->timestamp);

		/* Trailing information */
		fprintf(G.f_kis_xml, "\t\t<cdp-device></cdp-device>\n"
					 "\t\t<cdp-portid></cdp-portid>\n");

		/* Closing tag for the current wireless network */
		fprintf(G.f_kis_xml, "\t</wireless-network>\n");
		//-------- End of XML

        ap_cur = ap_cur->next;
    }

	/* Write all unassociated stations */
	st_cur = G.st_1st;
	while (st_cur != NULL) {
		/* If not associated and not Broadcast Mac */
		if ( st_cur->base == NULL || memcmp(st_cur->base->bssid, BROADCAST, 6) == 0 )
		{
			++network_number; // Network Number

			/* Write new network information */
			strncpy(first_time, ctime(&st_cur->tinit), TIME_STR_LENGTH - 1);
			first_time[strlen(first_time) - 1] = 0; // remove new line
			
			strncpy(last_time, ctime(&st_cur->tlast), TIME_STR_LENGTH - 1);
			last_time[strlen(last_time) - 1] = 0; // remove new line
			
			fprintf(G.f_kis_xml, "\t<wireless-network number=\"%d\" type=\"probe\" ",
				network_number);
			fprintf(G.f_kis_xml, "first-time=\"%s\" last-time=\"%s\">\n", first_time, last_time);

			/* BSSID */
			fprintf( G.f_kis_xml, "\t\t<BSSID>%02X:%02X:%02X:%02X:%02X:%02X</BSSID>\n",
					 st_cur->stmac[0], st_cur->stmac[1],
					 st_cur->stmac[2], st_cur->stmac[3],
					 st_cur->stmac[4], st_cur->stmac[5] );

			/* Manufacturer, if set using standard oui list */
			manuf = sanitize_xml((unsigned char *)st_cur->manuf, strlen(st_cur->manuf));
			fprintf(G.f_kis_xml, "\t\t<manuf>%s</manuf>\n", (manuf != NULL) ? manuf : "Unknown");
			free(manuf);

			/* Channel
			   FIXME: Take G.freqoption in account */
			fprintf(G.f_kis_xml, "\t\t<channel>%d</channel>\n", st_cur->channel);

			/* Freq (in Mhz) and total number of packet on that frequency
			   FIXME: Take G.freqoption in account */
			fprintf(G.f_kis_xml, "\t\t<freqmhz>%d %ld</freqmhz>\n",
						getFrequencyFromChannel(st_cur->channel),
						st_cur->nb_pkt );

			/* Rate: inaccurate because it's the latest rate seen */
			client_max_rate = ( st_cur->rate_from > st_cur->rate_to ) ? st_cur->rate_from : st_cur->rate_to ;
			fprintf(G.f_kis_xml, "\t\t<maxseenrate>%.6f</maxseenrate>\n", client_max_rate / 1000000.0 );

			fprintf(G.f_kis_xml, "\t\t<carrier>IEEE 802.11b+</carrier>\n");
			fprintf(G.f_kis_xml, "\t\t<encoding>CCK</encoding>\n");

			/* Packets */
			fprintf(G.f_kis_xml, "\t\t<packets>\n"
					"\t\t\t<LLC>0</LLC>\n"
					"\t\t\t<data>0</data>\n"
					"\t\t\t<crypt>0</crypt>\n"
					"\t\t\t<total>%ld</total>\n"
					"\t\t\t<fragments>0</fragments>\n"
					"\t\t\t<retries>0</retries>\n"
					"\t\t</packets>\n",
					st_cur->nb_pkt);

			/* XXX: What does that field mean? Is it the total size of data? */
			fprintf(G.f_kis_xml, "\t\t<datasize>0</datasize>\n");
	
			/* SNR information */
			average_power = (st_cur->power == -1) ? 0 : st_cur->power;
			fprintf(G.f_kis_xml, "\t\t<snr-info>\n"
						"\t\t\t<last_signal_dbm>%d</last_signal_dbm>\n"
						"\t\t\t<last_noise_dbm>0</last_noise_dbm>\n"
						"\t\t\t<last_signal_rssi>%d</last_signal_rssi>\n"
						"\t\t\t<last_noise_rssi>0</last_noise_rssi>\n"
						"\t\t\t<min_signal_dbm>%d</min_signal_dbm>\n"
						"\t\t\t<min_noise_dbm>0</min_noise_dbm>\n"
						"\t\t\t<min_signal_rssi>1024</min_signal_rssi>\n"
						"\t\t\t<min_noise_rssi>1024</min_noise_rssi>\n"
						"\t\t\t<max_signal_dbm>%d</max_signal_dbm>\n"
						"\t\t\t<max_noise_dbm>0</max_noise_dbm>\n"
						"\t\t\t<max_signal_rssi>%d</max_signal_rssi>\n"
						"\t\t\t<max_noise_rssi>0</max_noise_rssi>\n"
						 "\t\t</snr-info>\n",
						 average_power, average_power, average_power,
						 average_power, average_power );

			/* GPS Coordinates
			   XXX: We don't have GPS coordinates for clients */
			if (G.usegpsd)
			{
				fprintf(G.f_kis_xml, "\t\t<gps-info>\n"
							"\t\t\t<min-lat>%.6f</min-lat>\n"
							"\t\t\t<min-lon>%.6f</min-lon>\n"
							"\t\t\t<min-alt>%.6f</min-alt>\n"
							"\t\t\t<min-spd>%.6f</min-spd>\n"
							"\t\t\t<max-lat>%.6f</max-lat>\n"
							"\t\t\t<max-lon>%.6f</max-lon>\n"
							"\t\t\t<max-alt>%.6f</max-alt>\n"
							"\t\t\t<max-spd>%.6f</max-spd>\n"
							"\t\t\t<peak-lat>%.6f</peak-lat>\n"
							"\t\t\t<peak-lon>%.6f</peak-lon>\n"
							"\t\t\t<peak-alt>%.6f</peak-alt>\n"
							"\t\t\t<avg-lat>%.6f</avg-lat>\n"
							"\t\t\t<avg-lon>%.6f</avg-lon>\n"
							"\t\t\t<avg-alt>%.6f</avg-alt>\n"
							 "\t\t</gps-info>\n",
							 0.0, 0.0, 0.0, 0.0,
							 0.0, 0.0, 0.0, 0.0,
							 0.0, 0.0, 0.0,
							 0.0, 0.0, 0.0 );
			}

			fprintf(G.f_kis_xml, "\t\t<bsstimestamp>0</bsstimestamp>\n");

			/* CDP information */
			fprintf(G.f_kis_xml, "\t\t<cdp-device></cdp-device>\n"
					 	"\t\t<cdp-portid></cdp-portid>\n");


			/* Write client information */
			dump_write_kismet_netxml_client_info(st_cur, 1);

			fprintf(G.f_kis_xml, "\t</wireless-network>");
		}
		st_cur = st_cur->next;
	}
	/* TODO: Also go through na_1st */

	/* Trailing */
    fprintf( G.f_kis_xml, "%s\n", KISMET_NETXML_TRAILER );

    fflush( G.f_kis_xml );

    /* Sometimes there can be crap at the end of the file, so truncating is a good idea.
       XXX: Is this really correct, I hope fileno() won't have any side effect */
	unused = ftruncate(fileno(G.f_kis_xml), ftell( G.f_kis_xml ) );

    return 0;
}
#undef TIME_STR_LENGTH

#define KISMET_HEADER "Network;NetType;ESSID;BSSID;Info;Channel;Cloaked;Encryption;Decrypted;MaxRate;MaxSeenRate;Beacon;LLC;Data;Crypt;Weak;Total;Carrier;Encoding;FirstTime;LastTime;BestQuality;BestSignal;BestNoise;GPSMinLat;GPSMinLon;GPSMinAlt;GPSMinSpd;GPSMaxLat;GPSMaxLon;GPSMaxAlt;GPSMaxSpd;GPSBestLat;GPSBestLon;GPSBestAlt;DataSize;IPType;IP;\n"


int dump_write_kismet_csv( void )
{
    int i, k;
//     struct tm *ltime;
/*    char ssid_list[512];*/
    struct AP_info *ap_cur;

    if (! G.record_data || !G.output_format_kismet_csv)
    	return 0;

    fseek( G.f_kis, 0, SEEK_SET );

    fprintf( G.f_kis, KISMET_HEADER );

    ap_cur = G.ap_1st;

    k=1;
    while( ap_cur != NULL )
    {
        if( memcmp( ap_cur->bssid, BROADCAST, 6 ) == 0 )
        {
            ap_cur = ap_cur->next;
            continue;
        }

        if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
        {
            ap_cur = ap_cur->next;
            continue;
        }

        if(is_filtered_essid(ap_cur->essid) || ap_cur->nb_pkt < 2)
        {
            ap_cur = ap_cur->next;
            continue;
        }

        //Network
        fprintf( G.f_kis, "%d;", k );

        //NetType
        fprintf( G.f_kis, "infrastructure;");

        //ESSID
        for(i=0; i<ap_cur->ssid_length; i++)
        {
            fprintf( G.f_kis, "%c", ap_cur->essid[i] );
        }
        fprintf( G.f_kis, ";" );

        //BSSID
        fprintf( G.f_kis, "%02X:%02X:%02X:%02X:%02X:%02X;",
                 ap_cur->bssid[0], ap_cur->bssid[1],
                 ap_cur->bssid[2], ap_cur->bssid[3],
                 ap_cur->bssid[4], ap_cur->bssid[5] );

        //Info
        fprintf( G.f_kis, ";");

        //Channel
        fprintf( G.f_kis, "%d;", ap_cur->channel);

        //Cloaked
        fprintf( G.f_kis, "No;");

        //Encryption
        if( (ap_cur->security & (STD_OPN|STD_WEP|STD_WPA|STD_WPA2)) != 0)
        {
            if( ap_cur->security & STD_WPA2 ) fprintf( G.f_kis, "WPA2," );
            if( ap_cur->security & STD_WPA  ) fprintf( G.f_kis, "WPA," );
            if( ap_cur->security & STD_WEP  ) fprintf( G.f_kis, "WEP," );
            if( ap_cur->security & STD_OPN  ) fprintf( G.f_kis, "OPN," );
        }

        if( (ap_cur->security & (ENC_WEP|ENC_TKIP|ENC_WRAP|ENC_CCMP|ENC_WEP104|ENC_WEP40)) == 0 ) fprintf( G.f_kis, "None,");
        else
        {
            if( ap_cur->security & ENC_CCMP   ) fprintf( G.f_kis, "AES-CCM,");
            if( ap_cur->security & ENC_WRAP   ) fprintf( G.f_kis, "WRAP,");
            if( ap_cur->security & ENC_TKIP   ) fprintf( G.f_kis, "TKIP,");
            if( ap_cur->security & ENC_WEP104 ) fprintf( G.f_kis, "WEP104,");
            if( ap_cur->security & ENC_WEP40  ) fprintf( G.f_kis, "WEP40,");
/*            if( ap_cur->security & ENC_WEP    ) fprintf( G.f_kis, " WEP,");*/
        }

        fseek(G.f_kis, -1, SEEK_CUR);
        fprintf(G.f_kis, ";");

        //Decrypted
        fprintf( G.f_kis, "No;");

        //MaxRate
        fprintf( G.f_kis, "%d.0;", ap_cur->max_speed );

        //MaxSeenRate
        fprintf( G.f_kis, "0;");

        //Beacon
        fprintf( G.f_kis, "%ld;", ap_cur->nb_bcn);

        //LLC
        fprintf( G.f_kis, "0;");

        //Data
        fprintf( G.f_kis, "%ld;", ap_cur->nb_data );

        //Crypt
        fprintf( G.f_kis, "0;");

        //Weak
        fprintf( G.f_kis, "0;");

        //Total
        fprintf( G.f_kis, "%ld;", ap_cur->nb_data );

        //Carrier
        fprintf( G.f_kis, ";");

        //Encoding
        fprintf( G.f_kis, ";");

        //FirstTime
        fprintf( G.f_kis, "%s", ctime(&ap_cur->tinit) );
        fseek(G.f_kis, -1, SEEK_CUR);
        fprintf( G.f_kis, ";");

        //LastTime
        fprintf( G.f_kis, "%s", ctime(&ap_cur->tlast) );
        fseek(G.f_kis, -1, SEEK_CUR);
        fprintf( G.f_kis, ";");

        //BestQuality
        fprintf( G.f_kis, "%d;", ap_cur->avg_power );

        //BestSignal
        fprintf( G.f_kis, "0;" );

        //BestNoise
        fprintf( G.f_kis, "0;" );

        //GPSMinLat
        fprintf( G.f_kis, "%.6f;", ap_cur->gps_loc_min[0]);

        //GPSMinLon
        fprintf( G.f_kis, "%.6f;", ap_cur->gps_loc_min[1]);

        //GPSMinAlt
        fprintf( G.f_kis, "%.6f;", ap_cur->gps_loc_min[2]);

        //GPSMinSpd
        fprintf( G.f_kis, "%.6f;", ap_cur->gps_loc_min[3]);

        //GPSMaxLat
        fprintf( G.f_kis, "%.6f;", ap_cur->gps_loc_max[0]);

        //GPSMaxLon
        fprintf( G.f_kis, "%.6f;", ap_cur->gps_loc_max[1]);

        //GPSMaxAlt
        fprintf( G.f_kis, "%.6f;", ap_cur->gps_loc_max[2]);

        //GPSMaxSpd
        fprintf( G.f_kis, "%.6f;", ap_cur->gps_loc_max[3]);

        //GPSBestLat
        fprintf( G.f_kis, "%.6f;", ap_cur->gps_loc_best[0]);

        //GPSBestLon
        fprintf( G.f_kis, "%.6f;", ap_cur->gps_loc_best[1]);

        //GPSBestAlt
        fprintf( G.f_kis, "%.6f;", ap_cur->gps_loc_best[2]);

        //DataSize
        fprintf( G.f_kis, "0;" );

        //IPType
        fprintf( G.f_kis, "0;" );

        //IP
        fprintf( G.f_kis, "%d.%d.%d.%d;",
                 ap_cur->lanip[0], ap_cur->lanip[1],
                 ap_cur->lanip[2], ap_cur->lanip[3] );

        fprintf( G.f_kis, "\r\n");

        ap_cur = ap_cur->next;
        k++;
    }

    fflush( G.f_kis );
    return 0;
}

/* See if a string contains a character in the first "n" bytes.
 * 
 * Returns a pointer to the first occurrence of the character, or NULL
 * if the character is not present in the string.
 * 
 * Breaks the str* naming convention to avoid a name collision if we're
 * compiling on a system that has strnchr()
 */
static char *strchr_n(char *str, int c, size_t n)
{
	size_t count = 0;
	if (str == NULL || n == 0)
	{
		return NULL;
	}
	while(*str != c && *str != '\0' && count < n)
	{
		str++;
		count++;
	}

	return (*str == c) ? str : NULL;
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
static int read_line(int sock, char *buffer, int pos, int size)
{
	int status = 1;
	if (pos < 0 || size < 1 || pos >= size || buffer == NULL || sock < 0)
	{
		return -1;
	}
	while(strchr_n(buffer, 0x0A, pos) == NULL && status > 0  && pos < size )
	{
		status = recv(sock, buffer+pos, size-pos, 0);
		if(status > 0)
		{
			pos += status;
		}
	}

	if(status <= 0)
	{
		return status;
	}
	else if(pos == size && strchr_n(buffer, 0x0A, pos) == NULL)
	{
		return -1;
	}
	
	return pos;
}

/* Remove a newline-terminated block of data from a buffer, replacing 
 * the newline with a '\0'.
 * 
 * Returns the number of characters left in the buffer, or -1 if the 
 * buffer did not contain a newline.
 */
static int get_line_from_buffer(char *buffer, int size, char *line)
{
	char *cursor = strchr_n(buffer, 0x0A, size);
	if(NULL != cursor)
	{
		*cursor = '\0';
		cursor++;
		strcpy(line, buffer);
		memmove(buffer, cursor, size - (strlen(line) + 1));
		return size - (strlen(line) + 1);
	}
	
	return -1;
} 

/* Extract a name:value pair from a null-terminated line of JSON.
 * 
 * Returns 1 if the name was found, or 0 otherwise. 
 * 
 * The string in "value" is null-terminated if the name was found.  If
 * the name was not found, the contents of "value" are undefined. 
 */
static int json_get_value_for_name( const char *buffer, const char *name, char *value )
{
	char * to_find;
	char *cursor;
	size_t to_find_len;
	char *vcursor = value;
	int ret = 0;
	
	if (buffer == NULL || strlen(buffer) == 0 || name == NULL || strlen(name) == 0 || value == NULL)
	{
		return 0;
	}

	to_find_len = strlen(name) + 3;
	to_find = (char*) malloc(to_find_len);
	snprintf(to_find, sizeof(to_find), "\"%s\"", name);
	cursor = strstr(buffer, to_find);
	free(to_find);
	if(cursor != NULL)
	{
		cursor += to_find_len -1;
		while(*cursor != ':' && *cursor != '\0')
		{
			cursor++;
		}
		if(*cursor != '\0')
		{
			cursor++;
			while(isspace(*cursor) && *cursor != '\0')
			{
				cursor++;
			}
		}
		if('\0' == *cursor)
		{
			return 0;
		}

		if('"' == *cursor)
		{
			/* Quoted string */
			cursor++;
			while(*cursor != '"' && *cursor != '\0')
			{
				if('\\' == *cursor && '"' == *(cursor+1))
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
		else if(strncmp(cursor, "true", 4) == 0)
		{
			/* Boolean */
			strcpy(value, "true");
			ret = 1;
		}
		else if(strncmp(cursor, "false", 5) == 0)
		{
			/* Boolean */
			strcpy(value, "false");
			ret = 1;
		}
		else if('{' == *cursor || '[' == *cursor)
		{
			/* Object or array.  Too hard to handle and not needed for
			 * getting coords from GPSD, so pretend we didn't see anything.
			 */
			ret = 0;
		}
		else
		{
			/* Number, supposedly.  Copy as-is. */
			while(*cursor != ',' && *cursor != '}' && !isspace(*cursor))
			{
				*vcursor = *cursor;
				cursor++; vcursor++;
			}
			*vcursor = '\0';
			ret = 1;
		}
	}

	return ret;
}

void gps_tracker( void )
{
	ssize_t unused;
    int gpsd_sock;
    char line[1537], buffer[1537], data[1537];
    char *temp;
    struct sockaddr_in gpsd_addr;
    int ret, is_json, pos;
    int mode;
    fd_set read_fd;
    struct timeval timeout;
    memset(line, 0, 1537);
    memset(buffer, 0, 1537);
    memset(data, 0, 1537);

    /* attempt to connect to localhost, port 2947 */

    pos = 0;
    gpsd_sock = socket( AF_INET, SOCK_STREAM, 0 );

    if( gpsd_sock < 0 ) {
        return;
    }

    gpsd_addr.sin_family      = AF_INET;
    gpsd_addr.sin_port        = htons( 2947 );
    gpsd_addr.sin_addr.s_addr = inet_addr( "127.0.0.1" );

    if( connect( gpsd_sock, (struct sockaddr *) &gpsd_addr,
                 sizeof( gpsd_addr ) ) < 0 ) {
        return;
    }

    // Check if it's GPSd < 2.92 or the new one
    // 2.92+ immediately sends version information
    // < 2.92 requires to send PVTAD command
    FD_ZERO(&read_fd);
    FD_SET(gpsd_sock, &read_fd);
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    is_json = select(gpsd_sock + 1, &read_fd, NULL, NULL, &timeout);
    
    if (is_json > 0) {
		/* Probably JSON.  Read the first line and verify it's a version of the protocol we speak. */

    	if((pos = read_line(gpsd_sock, buffer, 0, sizeof(buffer))) <= 0)
    		return;
    	
    	pos = get_line_from_buffer(buffer, pos, line);

    	is_json = (json_get_value_for_name(line, "class", data) &&
    			   strncmp(data, "VERSION", 7) == 0);
		
    	if (is_json) {
			/* Verify it's a version of the protocol we speak */
			if(json_get_value_for_name(line, "proto_major", data) && data[0] != '3')
			{
				/* It's an unknown version of the protocol.  Bail out. */
				return;
			}
			
			// Send ?WATCH={"json":true};
			memset(line, 0, sizeof(line));
			strcpy(line, "?WATCH={\"json\":true};\n");
			if(send(gpsd_sock, line, 22, 0) != 22)
			{
				return;
			}
			// Device check removed -- if there isn't a device, just
			// read and discard lines until the user plugs one in, at
			// which point GPSD will start emitting coordinates.
    	}
    }
    else if(is_json < 0)
    {
		/* An error occurred while we were waiting for data */
		return;
	}
	/* Else select() returned zero (timeout expired) and we assume we're
	 * connected to an old-style gpsd. */

    /* loop reading the GPS coordinates */
    while( G.do_exit == 0 )
    {
        usleep( 500000 );
        memset( G.gps_loc, 0, sizeof( float ) * 5 );

        /* read position, speed, heading, altitude */
        if (is_json) {
        	// Format definition: http://catb.org/gpsd/gpsd_json.html

		if( (pos = read_line(gpsd_sock, buffer, pos, sizeof(buffer))) <= 0 )
		{
			return;
		}
		pos = get_line_from_buffer(buffer, pos, line);

		// See if we got a TPV report
		if(!json_get_value_for_name(line, "class", data) ||
			strncmp(data, "TPV", 3) != 0)
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
		if(!json_get_value_for_name(line, "mode", data) ||
			(mode = atoi(data)) < 2)
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

        	// Latitude
        	if(!json_get_value_for_name(line, "lat", data))
			continue;
		if(1 != sscanf(data, "%f", &G.gps_loc[0]))
			continue;

		// Longitude
		if(!json_get_value_for_name(line, "lon", data))
			continue;
		if(1 != sscanf(data, "%f", &G.gps_loc[1]))
			continue;

		// Altitude
		if(3 == mode)
		{
			if(!json_get_value_for_name(line, "alt", data))
				continue;
			if(1 != sscanf(data, "%f", &G.gps_loc[4]))
				continue;
		}
		else
		{
			G.gps_loc[4] = 0;
		}

		// Speed
		if(!json_get_value_for_name(line, "speed", data))
		{
			G.gps_loc[2] = 0;
		}
		else
		{
			if(1 != sscanf(data, "%f", &G.gps_loc[2]))
				G.gps_loc[2] = 0;
		}

		// Heading
		if(!json_get_value_for_name(line, "track", data))
		{
			G.gps_loc[3] = 0;
		}
		else
		{
			if(1 != sscanf(data, "%f", &G.gps_loc[3]))
				G.gps_loc[3] = 0;
		}
        } else {
        	memset( line, 0, sizeof( line ) );

			snprintf( line,  sizeof( line ) - 1, "PVTAD\r\n" );
			if( send( gpsd_sock, line, 7, 0 ) != 7 )
				return;

			memset( line, 0, sizeof( line ) );
			if( recv( gpsd_sock, line, sizeof( line ) - 1, 0 ) <= 0 )
				return;

			if( memcmp( line, "GPSD,P=", 7 ) != 0 )
				continue;

			/* make sure the coordinates are present */

			if( line[7] == '?' )
				continue;

			ret = sscanf( line + 7, "%f %f", &G.gps_loc[0], &G.gps_loc[1] );

			if( ( temp = strstr( line, "V=" ) ) == NULL ) continue;
			ret = sscanf( temp + 2, "%f", &G.gps_loc[2] ); /* speed */

			if( ( temp = strstr( line, "T=" ) ) == NULL ) continue;
			ret = sscanf( temp + 2, "%f", &G.gps_loc[3] ); /* heading */

			if( ( temp = strstr( line, "A=" ) ) == NULL ) continue;
			ret = sscanf( temp + 2, "%f", &G.gps_loc[4] ); /* altitude */
        }

        if (G.record_data)
			fputs( line, G.f_gps );

		G.save_gps = 1;

        if (G.do_exit == 0)
		{
			unused = write( G.gc_pipe[1], G.gps_loc, sizeof( float ) * 5 );
			kill( getppid(), SIGUSR2 );
		}
    }
}

void sighandler( int signum)
{
	ssize_t unused;
    int card=0;

    signal( signum, sighandler );

    if( signum == SIGUSR1 )
    {
		unused = read( G.cd_pipe[0], &card, sizeof(int) );
        if(G.freqoption)
            unused = read( G.ch_pipe[0], &(G.frequency[card]), sizeof( int ) );
        else
            unused = read( G.ch_pipe[0], &(G.channel[card]), sizeof( int ) );
    }

    if( signum == SIGUSR2 )
        unused = read( G.gc_pipe[0], &G.gps_loc, sizeof( float ) * 5 );

    if( signum == SIGINT || signum == SIGTERM )
    {
	reset_term();
        alarm( 1 );
        G.do_exit = 1;
        signal( SIGALRM, sighandler );
        dprintf( STDOUT_FILENO, "\n" );
    }

    if( signum == SIGSEGV )
    {
        fprintf( stderr, "Caught signal 11 (SIGSEGV). Please"
                         " contact the author!\33[?25h\n\n" );
        fflush( stdout );
        exit( 1 );
    }

    if( signum == SIGALRM )
    {
        dprintf( STDERR_FILENO, "Caught signal 14 (SIGALRM). Please"
                         " contact the author!\33[?25h\n\n" );
        _exit( 1 );
    }

    if( signum == SIGCHLD )
        wait( NULL );

    if( signum == SIGWINCH )
    {
        fprintf( stderr, "\33[2J" );
        fflush( stdout );
    }
}

int send_probe_request(struct wif *wi)
{
    int len;
    unsigned char p[4096], r_smac[6];

    memcpy(p, PROBE_REQ, 24);

    len = 24;

    p[24] = 0x00;      //ESSID Tag Number
    p[25] = 0x00;      //ESSID Tag Length

    len += 2;

    memcpy(p+len, RATES, 16);

    len += 16;

    r_smac[0] = 0x00;
    r_smac[1] = rand() & 0xFF;
    r_smac[2] = rand() & 0xFF;
    r_smac[3] = rand() & 0xFF;
    r_smac[4] = rand() & 0xFF;
    r_smac[5] = rand() & 0xFF;

    memcpy(p+10, r_smac, 6);

    if (wi_write(wi, p, len, NULL) == -1) {
        switch (errno) {
        case EAGAIN:
        case ENOBUFS:
            usleep(10000);
            return 0; /* XXX not sure I like this... -sorbo */
        }

        perror("wi_write()");
        return -1;
    }

    return 0;
}

int send_probe_requests(struct wif *wi[], int cards)
{
    int i=0;
    for(i=0; i<cards; i++)
    {
        send_probe_request(wi[i]);
    }
    return 0;
}

int getchancount(int valid)
{
    int i=0, chan_count=0;

    while(G.channels[i])
    {
        i++;
        if(G.channels[i] != -1)
            chan_count++;
    }

    if(valid) return chan_count;
    return i;
}

int getfreqcount(int valid)
{
    int i=0, freq_count=0;

    while(G.own_frequencies[i])
    {
        i++;
        if(G.own_frequencies[i] != -1)
            freq_count++;
    }

    if(valid) return freq_count;
    return i;
}

void channel_hopper(struct wif *wi[], int if_num, int chan_count )
{
	ssize_t unused;
    int ch, ch_idx = 0, card=0, chi=0, cai=0, j=0, k=0, first=1, again=1;
    int dropped=0;

    while( getppid() != 1 )
    {
        for( j = 0; j < if_num; j++ )
        {
            again = 1;

            ch_idx = chi % chan_count;

            card = cai % if_num;

            ++chi;
            ++cai;

            if( G.chswitch == 2 && !first )
            {
                j = if_num - 1;
                card = if_num - 1;

                if( getchancount(1) > if_num )
                {
                    while( again )
                    {
                        again = 0;
                        for( k = 0; k < ( if_num - 1 ); k++ )
                        {
                            if( G.channels[ch_idx] == G.channel[k] )
                            {
                                again = 1;
                                ch_idx = chi % chan_count;
                                chi++;
                            }
                        }
                    }
                }
            }

            if( G.channels[ch_idx] == -1 )
            {
                j--;
                cai--;
                dropped++;
                if(dropped >= chan_count)
                {
                    ch = wi_get_channel(wi[card]);
                    G.channel[card] = ch;
                    unused = write( G.cd_pipe[1], &card, sizeof(int) );
                    unused = write( G.ch_pipe[1], &ch, sizeof( int ) );
                    kill( getppid(), SIGUSR1 );
                    usleep(1000);
                }
                continue;
            }

            dropped = 0;

            ch = G.channels[ch_idx];

            if(wi_set_channel(wi[card], ch ) == 0 )
            {
                G.channel[card] = ch;
                unused = write( G.cd_pipe[1], &card, sizeof(int) );
                unused = write( G.ch_pipe[1], &ch, sizeof( int ) );
                if(G.active_scan_sim > 0)
                    send_probe_request(wi[card]);
                kill( getppid(), SIGUSR1 );
                usleep(1000);
            }
            else
            {
                G.channels[ch_idx] = -1;      /* remove invalid channel */
                j--;
                cai--;
                continue;
            }
        }

        if(G.chswitch == 0)
        {
            chi=chi-(if_num - 1);
        }

        if(first)
        {
            first = 0;
        }

        usleep( (G.hopfreq*1000) );
    }

    exit( 0 );
}

void frequency_hopper(struct wif *wi[], int if_num, int chan_count )
{
	ssize_t unused;
    int ch, ch_idx = 0, card=0, chi=0, cai=0, j=0, k=0, first=1, again=1;
    int dropped=0;

    while( getppid() != 1 )
    {
        for( j = 0; j < if_num; j++ )
        {
            again = 1;

            ch_idx = chi % chan_count;

            card = cai % if_num;

            ++chi;
            ++cai;

            if( G.chswitch == 2 && !first )
            {
                j = if_num - 1;
                card = if_num - 1;

                if( getfreqcount(1) > if_num )
                {
                    while( again )
                    {
                        again = 0;
                        for( k = 0; k < ( if_num - 1 ); k++ )
                        {
                            if( G.own_frequencies[ch_idx] == G.frequency[k] )
                            {
                                again = 1;
                                ch_idx = chi % chan_count;
                                chi++;
                            }
                        }
                    }
                }
            }

            if( G.own_frequencies[ch_idx] == -1 )
            {
                j--;
                cai--;
                dropped++;
                if(dropped >= chan_count)
                {
                    ch = wi_get_freq(wi[card]);
                    G.frequency[card] = ch;
                    unused = write( G.cd_pipe[1], &card, sizeof(int) );
                    unused = write( G.ch_pipe[1], &ch, sizeof( int ) );
                    kill( getppid(), SIGUSR1 );
                    usleep(1000);
                }
                continue;
            }

            dropped = 0;

            ch = G.own_frequencies[ch_idx];

            if(wi_set_freq(wi[card], ch ) == 0 )
            {
                G.frequency[card] = ch;
                unused = write( G.cd_pipe[1], &card, sizeof(int) );
                unused = write( G.ch_pipe[1], &ch, sizeof( int ) );
                kill( getppid(), SIGUSR1 );
                usleep(1000);
            }
            else
            {
                G.own_frequencies[ch_idx] = -1;      /* remove invalid channel */
                j--;
                cai--;
                continue;
            }
        }

        if(G.chswitch == 0)
        {
            chi=chi-(if_num - 1);
        }

        if(first)
        {
            first = 0;
        }

        usleep( (G.hopfreq*1000) );
    }

    exit( 0 );
}

int invalid_channel(int chan)
{
    int i=0;

    do
    {
        if (chan == abg_chans[i] && chan != 0 )
            return 0;
    } while (abg_chans[++i]);
    return 1;
}

int invalid_frequency(int freq)
{
    int i=0;

    do
    {
        if (freq == frequencies[i] && freq != 0 )
            return 0;
    } while (frequencies[++i]);
    return 1;
}

/* parse a string, for example "1,2,3-7,11" */

int getchannels(const char *optarg)
{
    unsigned int i=0,chan_cur=0,chan_first=0,chan_last=0,chan_max=128,chan_remain=0;
    char *optchan = NULL, *optc;
    char *token = NULL;
    int *tmp_channels;

    //got a NULL pointer?
    if(optarg == NULL)
        return -1;

    chan_remain=chan_max;

    //create a writable string
    optc = optchan = (char*) malloc(strlen(optarg)+1);
    strncpy(optchan, optarg, strlen(optarg));
    optchan[strlen(optarg)]='\0';

    tmp_channels = (int*) malloc(sizeof(int)*(chan_max+1));

    //split string in tokens, separated by ','
    while( (token = strsep(&optchan,",")) != NULL)
    {
        //range defined?
        if(strchr(token, '-') != NULL)
        {
            //only 1 '-' ?
            if(strchr(token, '-') == strrchr(token, '-'))
            {
                //are there any illegal characters?
                for(i=0; i<strlen(token); i++)
                {
                    if( (token[i] < '0') && (token[i] > '9') && (token[i] != '-'))
                    {
                        free(tmp_channels);
                        free(optc);
                        return -1;
                    }
                }

                if( sscanf(token, "%d-%d", &chan_first, &chan_last) != EOF )
                {
                    if(chan_first > chan_last)
                    {
                        free(tmp_channels);
                        free(optc);
                        return -1;
                    }
                    for(i=chan_first; i<=chan_last; i++)
                    {
                        if( (! invalid_channel(i)) && (chan_remain > 0) )
                        {
                                tmp_channels[chan_max-chan_remain]=i;
                                chan_remain--;
                        }
                    }
                }
                else
                {
                    free(tmp_channels);
                    free(optc);
                    return -1;
                }

            }
            else
            {
                free(tmp_channels);
                free(optc);
                return -1;
            }
        }
        else
        {
            //are there any illegal characters?
            for(i=0; i<strlen(token); i++)
            {
                if( (token[i] < '0') && (token[i] > '9') )
                {
                    free(tmp_channels);
                    free(optc);
                    return -1;
                }
            }

            if( sscanf(token, "%d", &chan_cur) != EOF)
            {
                if( (! invalid_channel(chan_cur)) && (chan_remain > 0) )
                {
                        tmp_channels[chan_max-chan_remain]=chan_cur;
                        chan_remain--;
                }

            }
            else
            {
                free(tmp_channels);
                free(optc);
                return -1;
            }
        }
    }

    G.own_channels = (int*) malloc(sizeof(int)*(chan_max - chan_remain + 1));

    for(i=0; i<(chan_max - chan_remain); i++)
    {
        G.own_channels[i]=tmp_channels[i];
    }

    G.own_channels[i]=0;

    free(tmp_channels);
    free(optc);
    if(i==1) return G.own_channels[0];
    if(i==0) return -1;
    return 0;
}

/* parse a string, for example "1,2,3-7,11" */

int getfrequencies(const char *optarg)
{
    unsigned int i=0,freq_cur=0,freq_first=0,freq_last=0,freq_max=10000,freq_remain=0;
    char *optfreq = NULL, *optc;
    char *token = NULL;
    int *tmp_frequencies;

    //got a NULL pointer?
    if(optarg == NULL)
        return -1;

    freq_remain=freq_max;

    //create a writable string
    optc = optfreq = (char*) malloc(strlen(optarg)+1);
    strncpy(optfreq, optarg, strlen(optarg));
    optfreq[strlen(optarg)]='\0';

    tmp_frequencies = (int*) malloc(sizeof(int)*(freq_max+1));

    //split string in tokens, separated by ','
    while( (token = strsep(&optfreq,",")) != NULL)
    {
        //range defined?
        if(strchr(token, '-') != NULL)
        {
            //only 1 '-' ?
            if(strchr(token, '-') == strrchr(token, '-'))
            {
                //are there any illegal characters?
                for(i=0; i<strlen(token); i++)
                {
                    if( (token[i] < '0' || token[i] > '9') && (token[i] != '-'))
                    {
                        free(tmp_frequencies);
                        free(optc);
                        return -1;
                    }
                }

                if( sscanf(token, "%d-%d", &freq_first, &freq_last) != EOF )
                {
                    if(freq_first > freq_last)
                    {
                        free(tmp_frequencies);
                        free(optc);
                        return -1;
                    }
                    for(i=freq_first; i<=freq_last; i++)
                    {
                        if( (! invalid_frequency(i)) && (freq_remain > 0) )
                        {
                                tmp_frequencies[freq_max-freq_remain]=i;
                                freq_remain--;
                        }
                    }
                }
                else
                {
                    free(tmp_frequencies);
                    free(optc);
                    return -1;
                }

            }
            else
            {
                free(tmp_frequencies);
                free(optc);
                return -1;
            }
        }
        else
        {
            //are there any illegal characters?
            for(i=0; i<strlen(token); i++)
            {
                if( (token[i] < '0') && (token[i] > '9') )
                {
                    free(tmp_frequencies);
                    free(optc);
                    return -1;
                }
            }

            if( sscanf(token, "%d", &freq_cur) != EOF)
            {
                if( (! invalid_frequency(freq_cur)) && (freq_remain > 0) )
                {
                        tmp_frequencies[freq_max-freq_remain]=freq_cur;
                        freq_remain--;
                }

                /* special case "-C 0" means: scan all available frequencies */
                if(freq_cur == 0)
                {
                    freq_first = 1;
                    freq_last = 9999;
                    for(i=freq_first; i<=freq_last; i++)
                    {
                        if( (! invalid_frequency(i)) && (freq_remain > 0) )
                        {
                                tmp_frequencies[freq_max-freq_remain]=i;
                                freq_remain--;
                        }
                    }
                }

            }
            else
            {
                free(tmp_frequencies);
                free(optc);
                return -1;
            }
        }
    }

    G.own_frequencies = (int*) malloc(sizeof(int)*(freq_max - freq_remain + 1));

    for(i=0; i<(freq_max - freq_remain); i++)
    {
        G.own_frequencies[i]=tmp_frequencies[i];
    }

    G.own_frequencies[i]=0;

    free(tmp_frequencies);
    free(optc);
    if(i==1) return G.own_frequencies[0];   //exactly 1 frequency given
    if(i==0) return -1;                     //error occured
    return 0;                               //frequency hopping
}

int setup_card(char *iface, struct wif **wis)
{
	struct wif *wi;

	wi = wi_open(iface);
	if (!wi)
		return -1;
	*wis = wi;

	return 0;
}

int init_cards(const char* cardstr, char *iface[], struct wif **wi)
{
    char *buffer;
    char *buf;
    int if_count=0;
    int i=0, again=0;

    buf = buffer = (char*) malloc( sizeof(char) * 1025 );
    strncpy( buffer, cardstr, 1025 );
    buffer[1024] = '\0';

    while( ((iface[if_count]=strsep(&buffer, ",")) != NULL) && (if_count < MAX_CARDS) )
    {
        again=0;
        for(i=0; i<if_count; i++)
        {
            if(strcmp(iface[i], iface[if_count]) == 0)
            again=1;
        }
        if(again) continue;
        if(setup_card(iface[if_count], &(wi[if_count])) != 0)
        {
            free(buf);
            return -1;
        }
        if_count++;
    }

    free(buf);
    return if_count;
}

#if 0
int get_if_num(const char* cardstr)
{
    char *buffer;
    int if_count=0;

    buffer = (char*) malloc(sizeof(char)*1025);
    if (buffer == NULL) {
		return -1;
	}

    strncpy(buffer, cardstr, 1025);
    buffer[1024] = '\0';

    while( (strsep(&buffer, ",") != NULL) && (if_count < MAX_CARDS) )
    {
        if_count++;
    }

    free(buffer)

    return if_count;
}
#endif

int set_encryption_filter(const char* input)
{
    if(input == NULL) return 1;

    if(strlen(input) < 3) return 1;

    if(strcasecmp(input, "opn") == 0)
        G.f_encrypt |= STD_OPN;

    if(strcasecmp(input, "wep") == 0)
        G.f_encrypt |= STD_WEP;

    if(strcasecmp(input, "wpa") == 0)
    {
        G.f_encrypt |= STD_WPA;
        G.f_encrypt |= STD_WPA2;
    }

    if(strcasecmp(input, "wpa1") == 0)
        G.f_encrypt |= STD_WPA;

    if(strcasecmp(input, "wpa2") == 0)
        G.f_encrypt |= STD_WPA2;

    return 0;
}

int check_monitor(struct wif *wi[], int *fd_raw, int *fdh, int cards)
{
    int i, monitor;
    char ifname[64];

    for(i=0; i<cards; i++)
    {
        monitor = wi_get_monitor(wi[i]);
        if(monitor != 0)
        {
            memset(G.message, '\x00', sizeof(G.message));
            snprintf(G.message, sizeof(G.message), "][ %s reset to monitor mode", wi_get_ifname(wi[i]));
            //reopen in monitor mode

            strncpy(ifname, wi_get_ifname(wi[i]), sizeof(ifname)-1);
            ifname[sizeof(ifname)-1] = 0;

            wi_close(wi[i]);
            wi[i] = wi_open(ifname);
            if (!wi[i]) {
                printf("Can't reopen %s\n", ifname);
                exit(1);
            }

            fd_raw[i] = wi_fd(wi[i]);
            if (fd_raw[i] > *fdh)
                *fdh = fd_raw[i];
        }
    }
    return 0;
}

int check_channel(struct wif *wi[], int cards)
{
    int i, chan;
    for(i=0; i<cards; i++)
    {
        chan = wi_get_channel(wi[i]);
        if(G.ignore_negative_one == 1 && chan==-1) return 0;
        if(G.channel[i] != chan)
        {
            memset(G.message, '\x00', sizeof(G.message));
            snprintf(G.message, sizeof(G.message), "][ fixed channel %s: %d ", wi_get_ifname(wi[i]), chan);
            wi_set_channel(wi[i], G.channel[i]);
        }
    }
    return 0;
}

int check_frequency(struct wif *wi[], int cards)
{
    int i, freq;
    for(i=0; i<cards; i++)
    {
        freq = wi_get_freq(wi[i]);
        if(freq < 0) continue;
        if(G.frequency[i] != freq)
        {
            memset(G.message, '\x00', sizeof(G.message));
            snprintf(G.message, sizeof(G.message), "][ fixed frequency %s: %d ", wi_get_ifname(wi[i]), freq);
            wi_set_freq(wi[i], G.frequency[i]);
        }
    }
    return 0;
}

int detect_frequencies(struct wif *wi)
{
    int start_freq = 2192;
    int end_freq = 2732;
    int max_freq_num = 2048; //should be enough to keep all available channels
    int freq=0, i=0;

    printf("Checking available frequencies, this could take few seconds.\n");

    frequencies = (int*) malloc((max_freq_num+1) * sizeof(int)); //field for frequencies supported
    memset(frequencies, 0, (max_freq_num+1) * sizeof(int));
    for(freq=start_freq; freq<=end_freq; freq+=5)
    {
        if(wi_set_freq(wi, freq) == 0)
        {
            frequencies[i] = freq;
            i++;
        }
        if(freq == 2482)
        {
            //special case for chan 14, as its 12MHz away from 13, not 5MHz
            freq = 2484;
            if(wi_set_freq(wi, freq) == 0)
            {
                frequencies[i] = freq;
                i++;
            }
            freq = 2482;
        }
    }

    //again for 5GHz channels
    start_freq=4800;
    end_freq=6000;
    for(freq=start_freq; freq<=end_freq; freq+=5)
    {
        if(wi_set_freq(wi, freq) == 0)
        {
            frequencies[i] = freq;
            i++;
        }
    }

    printf("Done.\n");
    return 0;
}

int array_contains(int *array, int length, int value)
{
    int i;
    for(i=0;i<length;i++)
        if(array[i] == value)
            return 1;

    return 0;
}

int rearrange_frequencies()
{
    int *freqs;
    int count, left, pos;
    int width, last_used=0;
    int cur_freq, last_freq, round_done;
//     int i;

    width = DEFAULT_CWIDTH;
    cur_freq=0;

    count = getfreqcount(0);
    left = count;
    pos = 0;

    freqs = malloc(sizeof(int) * (count + 1));
    memset(freqs, 0, sizeof(int) * (count + 1));
    round_done = 0;

    while(left > 0)
    {
//         printf("pos: %d\n", pos);
        last_freq = cur_freq;
        cur_freq = G.own_frequencies[pos%count];
        if(cur_freq == last_used)
            round_done=1;
//         printf("count: %d, left: %d, last_used: %d, cur_freq: %d, width: %d\n", count, left, last_used, cur_freq, width);
        if(((count-left) > 0) && !round_done && ( ABS( last_used-cur_freq ) < width ) )
        {
//             printf("skip it!\n");
            pos++;
            continue;
        }
        if(!array_contains( freqs, count, cur_freq))
        {
//             printf("not in there yet: %d\n", cur_freq);
            freqs[count - left] = cur_freq;
            last_used = cur_freq;
            left--;
            round_done = 0;
        }

        pos++;
    }

    memcpy(G.own_frequencies, freqs, count*sizeof(int));
    free(freqs);

    return 0;
}

int main( int argc, char *argv[] )
{
    long time_slept, cycle_time, cycle_time2;
    char * output_format_string;
    int caplen=0, i, j, fdh, fd_is_set, chan_count, freq_count, unused;
    int fd_raw[MAX_CARDS], arptype[MAX_CARDS];
    int ivs_only, found;
    int valid_channel;
    int freq [2];
    int num_opts = 0;
    int option = 0;
    int option_index = 0;
    char ifnam[64];
    int wi_read_failed=0;
    int n = 0;
    int output_format_first_time = 1;
#ifdef HAVE_PCRE
    const char *pcreerror;
    int pcreerroffset;
#endif

    struct AP_info *ap_cur, *ap_prv, *ap_next;
    struct ST_info *st_cur, *st_next;
    struct NA_info *na_cur, *na_next;
    struct oui *oui_cur, *oui_next;

    struct pcap_pkthdr pkh;

    time_t tt1, tt2, tt3, start_time;

    struct wif	       *wi[MAX_CARDS];
    struct rx_info     ri;
    unsigned char      tmpbuf[4096];
    unsigned char      buffer[4096];
    unsigned char      *h80211;
    char               *iface[MAX_CARDS];

    struct timeval     tv0;
    struct timeval     tv1;
    struct timeval     tv2;
    struct timeval     tv3;
    struct timeval     tv4;
    struct tm          *lt;

    /*
    struct sockaddr_in provis_addr;
    */

    fd_set             rfds;

    static struct option long_options[] = {
        {"band",     1, 0, 'b'},
        {"beacon",   0, 0, 'e'},
        {"beacons",  0, 0, 'e'},
        {"cswitch",  1, 0, 's'},
        {"netmask",  1, 0, 'm'},
        {"bssid",    1, 0, 'd'},
        {"essid",    1, 0, 'N'},
        {"essid-regex", 1, 0, 'R'},
        {"channel",  1, 0, 'c'},
        {"gpsd",     0, 0, 'g'},
        {"ivs",      0, 0, 'i'},
        {"write",    1, 0, 'w'},
        {"encrypt",  1, 0, 't'},
        {"update",   1, 0, 'u'},
        {"berlin",   1, 0, 'B'},
        {"help",     0, 0, 'H'},
        {"nodecloak",0, 0, 'D'},
        {"showack",  0, 0, 'A'},
        {"detect-anomaly", 0, 0, 'E'},
        {"output-format",  1, 0, 'o'},
        {"ignore-negative-one", 0, &G.ignore_negative_one, 1},
        {"manufacturer",  0, 0, 'M'},
        {"uptime",   0, 0, 'U'},
        {"write-interval", 1, 0, 'I'},
        {"wps",  0, 0, 'W'},
        {0,          0, 0,  0 }
    };


#ifdef USE_GCRYPT
    // Register callback functions to ensure proper locking in the sensitive parts of libgcrypt.
    gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
    // Disable secure memory.
    gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
    // Tell Libgcrypt that initialization has completed.
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
#endif
	pthread_mutex_init( &(G.mx_print), NULL );
    pthread_mutex_init( &(G.mx_sort), NULL );

    textstyle(TEXT_RESET);//(TEXT_RESET, TEXT_BLACK, TEXT_WHITE);

	/* initialize a bunch of variables */

	srand( time( NULL ) );
    memset( &G, 0, sizeof( G ) );

    h80211         =  NULL;
    ivs_only       =  0;
    G.chanoption   =  0;
    G.freqoption   =  0;
    G.num_cards	   =  0;
    fdh		   =  0;
    fd_is_set	   =  0;
    chan_count	   =  0;
    time_slept     =  0;
    G.batt         =  NULL;
    G.chswitch     =  0;
    valid_channel  =  0;
    G.usegpsd      =  0;
    G.channels     =  bg_chans;
    G.one_beacon   =  1;
    G.singlechan   =  0;
    G.singlefreq   =  0;
    G.dump_prefix  =  NULL;
    G.record_data  =  0;
    G.f_cap        =  NULL;
    G.f_ivs        =  NULL;
    G.f_txt        =  NULL;
    G.f_kis        =  NULL;
    G.f_kis_xml    =  NULL;
    G.f_gps        =  NULL;
    G.keyout       =  NULL;
    G.f_xor        =  NULL;
    G.sk_len       =  0;
    G.sk_len2      =  0;
    G.sk_start     =  0;
    G.prefix       =  NULL;
    G.f_encrypt    =  0;
    G.asso_client  =  0;
    G.f_essid      =  NULL;
    G.f_essid_count = 0;
    G.active_scan_sim  =  0;
    G.update_s     =  0;
    G.decloak      =  1;
    G.is_berlin    =  0;
    G.numaps       =  0;
    G.maxnumaps    =  0;
    G.berlin       =  120;
    G.show_ap      =  1;
    G.show_sta     =  1;
    G.show_ack     =  0;
    G.hide_known   =  0;
    G.maxsize_essid_seen  =  5; // Initial value: length of "ESSID"
    G.show_manufacturer = 0;
    G.show_uptime  = 0;
    G.hopfreq      =  DEFAULT_HOPFREQ;
    G.s_file       =  NULL;
    G.s_iface      =  NULL;
    G.f_cap_in     =  NULL;
    G.detect_anomaly = 0;
    G.airodump_start_time = NULL;
	G.manufList = NULL;

	G.output_format_pcap = 1;
    G.output_format_csv = 1;
    G.output_format_kismet_csv = 1;
    G.output_format_kismet_netxml = 1;
    G.file_write_interval = 5; // Write file every 5 seconds by default
    G.maxsize_wps_seen  =  6;
    G.show_wps     = 0;
#ifdef HAVE_PCRE
    G.f_essid_regex = NULL;
#endif

	// Default selection.
    resetSelection();

    memset(G.sharedkey, '\x00', 512*3);
    memset(G.message, '\x00', sizeof(G.message));
    memset(&G.pfh_in, '\x00', sizeof(struct pcap_file_header));

    gettimeofday( &tv0, NULL );

    lt = localtime( (time_t *) &tv0.tv_sec );

    G.keyout = (char*) malloc(512);
    memset( G.keyout, 0, 512 );
    snprintf( G.keyout,  511,
              "keyout-%02d%02d-%02d%02d%02d.keys",
              lt->tm_mon + 1, lt->tm_mday,
              lt->tm_hour, lt->tm_min, lt->tm_sec );

    for(i=0; i<MAX_CARDS; i++)
    {
        arptype[i]=0;
        fd_raw[i]=-1;
        G.channel[i]=0;
    }

    memset(G.f_bssid, '\x00', 6);
    memset(G.f_netmask, '\x00', 6);
    memset(G.wpa_bssid, '\x00', 6);


    /* check the arguments */

    for(i=0; long_options[i].name != NULL; i++);
    num_opts = i;

    for(i=0; i<argc; i++) //go through all arguments
    {
        found = 0;
        if(strlen(argv[i]) >= 3)
        {
            if(argv[i][0] == '-' && argv[i][1] != '-')
            {
                //we got a single dash followed by at least 2 chars
                //lets check that against our long options to find errors
                for(j=0; j<num_opts;j++)
                {
                    if( strcmp(argv[i]+1, long_options[j].name) == 0 )
                    {
                        //found long option after single dash
                        found = 1;
                        if(i>1 && strcmp(argv[i-1], "-") == 0)
                        {
                            //separated dashes?
                            printf("Notice: You specified \"%s %s\". Did you mean \"%s%s\" instead?\n", argv[i-1], argv[i], argv[i-1], argv[i]);
                        }
                        else
                        {
                            //forgot second dash?
                            printf("Notice: You specified \"%s\". Did you mean \"-%s\" instead?\n", argv[i], argv[i]);
                        }
                        break;
                    }
                }
                if(found)
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

        option = getopt_long( argc, argv,
                        "b:c:egiw:s:t:u:m:d:N:R:aHDB:Ahf:r:EC:o:x:MUI:W",
                        long_options, &option_index );

        if( option < 0 ) break;

        switch( option )
        {
            case 0 :

                break;

            case ':':

                printf("\"%s --help\" for help.\n", argv[0]);
                return( 1 );

            case '?':

                printf("\"%s --help\" for help.\n", argv[0]);
                return( 1 );

            case 'I':

            	if (!is_string_number(optarg)) {
            		printf("Error: Write interval is not a number (>0). Aborting.\n");
            		exit ( 1 );
            	}
            	
            	G.file_write_interval = atoi(optarg);
            	
            	if (G.file_write_interval <= 0) {
            		printf("Error: Write interval must be greater than 0. Aborting.\n");
            		exit ( 1 );
            	}
            	break;
                
			case 'E':
				G.detect_anomaly = 1;
				break;

            case 'e':

                G.one_beacon = 0;
                break;

            case 'a':

                G.asso_client = 1;
                break;

            case 'A':

                G.show_ack = 1;
                break;

            case 'h':

                G.hide_known = 1;
                break;

            case 'D':

                G.decloak = 0;
                break;

	    case 'M':

                G.show_manufacturer = 1;
                break;

	    case 'U' :
	    		G.show_uptime = 1;
	    		break;

            case 'W':

                G.show_wps = 1;
                break;

            case 'c' :

                if (G.channel[0] > 0 || G.chanoption == 1) {
                    if (G.chanoption == 1)
                        printf( "Notice: Channel range already given\n" );
                    else
                        printf( "Notice: Channel already given (%d)\n", G.channel[0]);
                    break;
                }

                G.channel[0] = getchannels(optarg);

                if ( G.channel[0] < 0 )
                    goto usage;

                G.chanoption = 1;

                if( G.channel[0] == 0 )
                {
                    G.channels = G.own_channels;
                    break;
                }
                G.channels = bg_chans;
                break;

            case 'C' :

                if (G.channel[0] > 0 || G.chanoption == 1) {
                    if (G.chanoption == 1)
                        printf( "Notice: Channel range already given\n" );
                    else
                        printf( "Notice: Channel already given (%d)\n", G.channel[0]);
                    break;
                }

                if (G.freqoption == 1) {
                    printf( "Notice: Frequency range already given\n" );
                    break;
                }

                G.freqstring = optarg;

                G.freqoption = 1;

                break;

            case 'b' :

                if (G.chanoption == 1 && option != 'c') {
                    printf( "Notice: Channel range already given\n" );
                    break;
                }
                freq[0] = freq[1] = 0;

                for (i = 0; i < (int)strlen(optarg); i++) {
                    if ( optarg[i] == 'a' )
                        freq[1] = 1;
                    else if ( optarg[i] == 'b' || optarg[i] == 'g')
                        freq[0] = 1;
                    else {
                        printf( "Error: invalid band (%c)\n", optarg[i] );
                        printf("\"%s --help\" for help.\n", argv[0]);
                        exit ( 1 );
                    }
                }

                if (freq[1] + freq[0] == 2 )
                    G.channels = abg_chans;
                else {
                    if ( freq[1] == 1 )
                        G.channels = a_chans;
                    else
                        G.channels = bg_chans;
                }

                break;

            case 'i':

				// Reset output format if it's the first time the option is specified
				if (output_format_first_time) {
					output_format_first_time = 0;

					G.output_format_pcap = 0;
					G.output_format_csv = 0;
					G.output_format_kismet_csv = 0;
    				G.output_format_kismet_netxml = 0;
				}

 				if (G.output_format_pcap) {
					printf( usage, getVersion("Airodump-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );
					fprintf(stderr, "Invalid output format: IVS and PCAP format cannot be used together.\n");
					return( 1 );
				}

                ivs_only = 1;
                break;

            case 'g':

                G.usegpsd  = 1;
                /*
                if (inet_aton(optarg, &provis_addr.sin_addr) == 0 )
                {
                    printf("Invalid IP address.\n");
                    return (1);
                }
                */
                break;

            case 'w':

                if (G.dump_prefix != NULL) {
                    printf( "Notice: dump prefix already given\n" );
                    break;
                }
                /* Write prefix */
                G.dump_prefix   = optarg;
                G.record_data = 1;
                break;

            case 'r' :

                if( G.s_file )
                {
                    printf( "Packet source already specified.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                G.s_file = optarg;
                break;

            case 's':

                if (atoi(optarg) > 2) {
                    goto usage;
                }
                if (G.chswitch != 0) {
                    printf("Notice: switching method already given\n");
                    break;
                }
                G.chswitch = atoi(optarg);
                break;

            case 'u':

                G.update_s = atoi(optarg);

                /* If failed to parse or value <= 0, use default, 100ms */
                if (G.update_s <= 0)
                	G.update_s = REFRESH_RATE;

                break;

            case 'f':

                G.hopfreq = atoi(optarg);

                /* If failed to parse or value <= 0, use default, 100ms */
                if (G.hopfreq <= 0)
                	G.hopfreq = DEFAULT_HOPFREQ;

                break;

            case 'B':

                G.is_berlin = 1;
                G.berlin    = atoi(optarg);

                if (G.berlin <= 0)
                	G.berlin = 120;

                break;

            case 'm':

                if ( memcmp(G.f_netmask, NULL_MAC, 6) != 0 )
                {
                    printf("Notice: netmask already given\n");
                    break;
                }
                if(getmac(optarg, 1, G.f_netmask) != 0)
                {
                    printf("Notice: invalid netmask\n");
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;

            case 'd':

                if ( memcmp(G.f_bssid, NULL_MAC, 6) != 0 )
                {
                    printf("Notice: bssid already given\n");
                    break;
                }
                if(getmac(optarg, 1, G.f_bssid) != 0)
                {
                    printf("Notice: invalid bssid\n");
                    printf("\"%s --help\" for help.\n", argv[0]);

                    return( 1 );
                }
                break;

            case 'N':

                G.f_essid_count++;
                G.f_essid = (char**)realloc(G.f_essid, G.f_essid_count * sizeof(char*));
                G.f_essid[G.f_essid_count-1] = optarg;
                break;

	    case 'R':

#ifdef HAVE_PCRE
                if (G.f_essid_regex != NULL)
                {
			printf("Error: ESSID regular expression already given. Aborting\n");
			exit(1);
                }

                G.f_essid_regex = pcre_compile(optarg, 0, &pcreerror, &pcreerroffset, NULL);

                if (G.f_essid_regex == NULL)
                {
			printf("Error: regular expression compilation failed at offset %d: %s; aborting\n", pcreerroffset, pcreerror);
			exit(1);
		}
#else
                printf("Error: Airodump-ng wasn't compiled with pcre support; aborting\n");
#endif

                break;

            case 't':

                set_encryption_filter(optarg);
                break;

			case 'o':

				// Reset output format if it's the first time the option is specified
				if (output_format_first_time) {
					output_format_first_time = 0;

					G.output_format_pcap = 0;
					G.output_format_csv = 0;
					G.output_format_kismet_csv = 0;
    				G.output_format_kismet_netxml = 0;
				}

				// Parse the value
				output_format_string = strtok(optarg, ",");
				while (output_format_string != NULL) {
					if (strlen(output_format_string) != 0) {
						if (strncasecmp(output_format_string, "csv", 3) == 0
							|| strncasecmp(output_format_string, "txt", 3) == 0) {
							G.output_format_csv = 1;
						} else if (strncasecmp(output_format_string, "pcap", 4) == 0
							|| strncasecmp(output_format_string, "cap", 3) == 0) {
                            if (ivs_only) {
                                printf( usage, getVersion("Airodump-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );
                                fprintf(stderr, "Invalid output format: IVS and PCAP format cannot be used together.\n");
                                return( 1 );
                            }
							G.output_format_pcap = 1;
						} else if (strncasecmp(output_format_string, "ivs", 3) == 0) {
                            if (G.output_format_pcap) {
                                printf( usage, getVersion("Airodump-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );
                                fprintf(stderr, "Invalid output format: IVS and PCAP format cannot be used together.\n");
                                return( 1 );
                            }
							ivs_only = 1;
						} else if (strncasecmp(output_format_string, "kismet", 6) == 0) {
							G.output_format_kismet_csv = 1;
						} else if (strncasecmp(output_format_string, "gps", 3) == 0) {
							G.usegpsd  = 1;
						} else if (strncasecmp(output_format_string, "netxml", 6) == 0
							|| strncasecmp(output_format_string, "newcore", 7) == 0
							|| strncasecmp(output_format_string, "kismet-nc", 9) == 0
							|| strncasecmp(output_format_string, "kismet_nc", 9) == 0
							|| strncasecmp(output_format_string, "kismet-newcore", 14) == 0
							|| strncasecmp(output_format_string, "kismet_newcore", 14) == 0) {
							G.output_format_kismet_netxml = 1;
						} else if (strncasecmp(output_format_string, "default", 6) == 0) {
							G.output_format_pcap = 1;
							G.output_format_csv = 1;
							G.output_format_kismet_csv = 1;
							G.output_format_kismet_netxml = 1;
						} else if (strncasecmp(output_format_string, "none", 6) == 0) {
							G.output_format_pcap = 0;
							G.output_format_csv = 0;
							G.output_format_kismet_csv = 0;
    						G.output_format_kismet_netxml = 0;

							G.usegpsd  = 0;
							ivs_only = 0;
						} else {
							// Display an error if it does not match any value
							fprintf(stderr, "Invalid output format: <%s>\n", output_format_string);
							exit(1);
						}
					}
					output_format_string = strtok(NULL, ",");
				}

				break;

            case 'H':

                printf( usage, getVersion("Airodump-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );
                return( 1 );

            case 'x':

                G.active_scan_sim = atoi(optarg);

                if (G.active_scan_sim <= 0)
                    G.active_scan_sim = 0;
                break;

            default : goto usage;
        }
    } while ( 1 );

    if( argc - optind != 1 && G.s_file == NULL)
    {
        if(argc == 1)
        {
usage:
            printf( usage, getVersion("Airodump-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );
        }
        if( argc - optind == 0)
        {
            printf("No interface specified.\n");
        }
        if(argc > 1)
        {
            printf("\"%s --help\" for help.\n", argv[0]);
        }
        return( 1 );
    }

    if( argc - optind == 1 )
        G.s_iface = argv[argc-1];

    if( ( memcmp(G.f_netmask, NULL_MAC, 6) != 0 ) && ( memcmp(G.f_bssid, NULL_MAC, 6) == 0 ) )
    {
        printf("Notice: specify bssid \"--bssid\" with \"--netmask\"\n");
        printf("\"%s --help\" for help.\n", argv[0]);
        return( 1 );
    }

    if (G.show_wps && G.show_manufacturer)
        G.maxsize_essid_seen += G.maxsize_wps_seen;

    if(G.s_iface != NULL)
    {
        /* initialize cards */
        G.num_cards = init_cards(G.s_iface, iface, wi);

        if(G.num_cards <= 0)
            return( 1 );

        for (i = 0; i < G.num_cards; i++) {
            fd_raw[i] = wi_fd(wi[i]);
            if (fd_raw[i] > fdh)
                fdh = fd_raw[i];
        }

        if(G.freqoption == 1 && G.freqstring != NULL) // use frequencies
        {
            detect_frequencies(wi[0]);
            G.frequency[0] = getfrequencies(G.freqstring);
            if(G.frequency[0] == -1)
            {
                printf("No valid frequency given.\n");
                return(1);
            }

//             printf("gonna rearrange\n");
            rearrange_frequencies();
//             printf("finished rearranging\n");

            freq_count = getfreqcount(0);

            /* find the interface index */
            /* start a child to hop between frequencies */

            if( G.frequency[0] == 0 )
            {
                unused = pipe( G.ch_pipe );
                unused = pipe( G.cd_pipe );

                signal( SIGUSR1, sighandler );

                if( ! fork() )
                {
                    /* reopen cards.  This way parent & child don't share resources for
                    * accessing the card (e.g. file descriptors) which may cause
                    * problems.  -sorbo
                    */
                    for (i = 0; i < G.num_cards; i++) {
                        strncpy(ifnam, wi_get_ifname(wi[i]), sizeof(ifnam)-1);
                        ifnam[sizeof(ifnam)-1] = 0;

                        wi_close(wi[i]);
                        wi[i] = wi_open(ifnam);
                        if (!wi[i]) {
                                printf("Can't reopen %s\n", ifnam);
                                exit(1);
                        }
                    }

					/* Drop privileges */
					if (setuid( getuid() ) == -1) {
						perror("setuid");
					}

                    frequency_hopper(wi, G.num_cards, freq_count);
                    exit( 1 );
                }
            }
            else
            {
                for( i=0; i<G.num_cards; i++ )
                {
                    wi_set_freq(wi[i], G.frequency[0]);
                    G.frequency[i] = G.frequency[0];
                }
                G.singlefreq = 1;
            }
        }
        else    //use channels
        {
            chan_count = getchancount(0);

            /* find the interface index */
            /* start a child to hop between channels */

            if( G.channel[0] == 0 )
            {
                unused = pipe( G.ch_pipe );
                unused = pipe( G.cd_pipe );

                signal( SIGUSR1, sighandler );

                if( ! fork() )
                {
                    /* reopen cards.  This way parent & child don't share resources for
                    * accessing the card (e.g. file descriptors) which may cause
                    * problems.  -sorbo
                    */
                    for (i = 0; i < G.num_cards; i++) {
                        strncpy(ifnam, wi_get_ifname(wi[i]), sizeof(ifnam)-1);
                        ifnam[sizeof(ifnam)-1] = 0;

                        wi_close(wi[i]);
                        wi[i] = wi_open(ifnam);
                        if (!wi[i]) {
                                printf("Can't reopen %s\n", ifnam);
                                exit(1);
                        }
                    }

					/* Drop privileges */
					if (setuid( getuid() ) == -1) {
						perror("setuid");
					}

                    channel_hopper(wi, G.num_cards, chan_count);
                    exit( 1 );
                }
            }
            else
            {
                for( i=0; i<G.num_cards; i++ )
                {
                    wi_set_channel(wi[i], G.channel[0]);
                    G.channel[i] = G.channel[0];
                }
                G.singlechan = 1;
            }
        }
    }

	/* Drop privileges */
	if (setuid( getuid() ) == -1) {
		perror("setuid");
	}

    /* check if there is an input file */
    if( G.s_file != NULL )
    {
        if( ! ( G.f_cap_in = fopen( G.s_file, "rb" ) ) )
        {
            perror( "open failed" );
            return( 1 );
        }

        n = sizeof( struct pcap_file_header );

        if( fread( &G.pfh_in, 1, n, G.f_cap_in ) != (size_t) n )
        {
            perror( "fread(pcap file header) failed" );
            return( 1 );
        }

        if( G.pfh_in.magic != TCPDUMP_MAGIC &&
            G.pfh_in.magic != TCPDUMP_CIGAM )
        {
            fprintf( stderr, "\"%s\" isn't a pcap file (expected "
                             "TCPDUMP_MAGIC).\n", G.s_file );
            return( 1 );
        }

        if( G.pfh_in.magic == TCPDUMP_CIGAM )
            SWAP32(G.pfh_in.linktype);

        if( G.pfh_in.linktype != LINKTYPE_IEEE802_11 &&
            G.pfh_in.linktype != LINKTYPE_PRISM_HEADER &&
            G.pfh_in.linktype != LINKTYPE_RADIOTAP_HDR &&
            G.pfh_in.linktype != LINKTYPE_PPI_HDR )
        {
            fprintf( stderr, "Wrong linktype from pcap file header "
                             "(expected LINKTYPE_IEEE802_11) -\n"
                             "this doesn't look like a regular 802.11 "
                             "capture.\n" );
            return( 1 );
        }
    }

    /* open or create the output files */

    if (G.record_data)
    	if( dump_initialize( G.dump_prefix, ivs_only ) )
    	    return( 1 );

    signal( SIGINT,   sighandler );
    signal( SIGSEGV,  sighandler );
    signal( SIGTERM,  sighandler );
    signal( SIGWINCH, sighandler );

    sighandler( SIGWINCH );

    /* fill oui struct if ram is greater than 32 MB */
    if (get_ram_size()  > MIN_RAM_SIZE_LOAD_OUI_RAM) {
        G.manufList = load_oui_file();
	}

    /* start the GPS tracker */

    if (G.usegpsd)
    {
        unused = pipe( G.gc_pipe );
        signal( SIGUSR2, sighandler );

        if( ! fork() )
        {
            gps_tracker();
            exit( 1 );
        }

        usleep( 50000 );
        waitpid( -1, NULL, WNOHANG );
    }

    fprintf( stderr, "\33[?25l\33[2J\n" );

    start_time = time( NULL );
    tt1        = time( NULL );
    tt2        = time( NULL );
    tt3        = time( NULL );
    gettimeofday( &tv3, NULL );
    gettimeofday( &tv4, NULL );

    G.batt     = getBatteryString();

    G.elapsed_time = (char *) calloc( 1, 4 );
    strncpy(G.elapsed_time, "0 s", 4 - 1);

	/* Create start time string for kismet netxml file */
    G.airodump_start_time = (char *) calloc( 1, 1000 * sizeof(char) );
    strncpy(G.airodump_start_time, ctime( & start_time ), 1000 - 1);
    G.airodump_start_time[strlen(G.airodump_start_time) - 1] = 0; // remove new line
    G.airodump_start_time = (char *) realloc( G.airodump_start_time, sizeof(char) * (strlen(G.airodump_start_time) + 1) );

    if( pthread_create( &(G.input_tid), NULL, (void *) input_thread, NULL ) != 0 )
    {
	perror( "pthread_create failed" );
	return 1;
    }


    while( 1 )
    {
        if( G.do_exit )
        {
            break;
        }

        if( time( NULL ) - tt1 >= G.file_write_interval )
        {
            /* update the text output files */

            tt1 = time( NULL );
            if (G. output_format_csv)  dump_write_csv();
            if (G.output_format_kismet_csv) dump_write_kismet_csv();
            if (G.output_format_kismet_netxml) dump_write_kismet_netxml();
        }

        if( time( NULL ) - tt2 > 5 )
        {
        	if( G.sort_by != SORT_BY_NOTHING) {
				/* sort the APs by power */
				pthread_mutex_lock( &(G.mx_sort) );
				dump_sort();
				pthread_mutex_unlock( &(G.mx_sort) );
        	}

            /* update the battery state */
            free(G.batt);
            G.batt = NULL;

            tt2 = time( NULL );
            G.batt = getBatteryString();

            /* update elapsed time */

            free(G.elapsed_time);
            G.elapsed_time=NULL;
            G.elapsed_time = getStringTimeFromSec(
            difftime(tt2, start_time) );


            /* flush the output files */

            if( G.f_cap != NULL ) fflush( G.f_cap );
            if( G.f_ivs != NULL ) fflush( G.f_ivs );
        }

        gettimeofday( &tv1, NULL );

        cycle_time = 1000000UL * ( tv1.tv_sec  - tv3.tv_sec  )
                             + ( tv1.tv_usec - tv3.tv_usec );

        cycle_time2 = 1000000UL * ( tv1.tv_sec  - tv4.tv_sec  )
                              + ( tv1.tv_usec - tv4.tv_usec );

        if( G.active_scan_sim > 0 && cycle_time2 > G.active_scan_sim*1000 )
        {
            gettimeofday( &tv4, NULL );
            send_probe_requests(wi, G.num_cards);
        }

        if( cycle_time > 500000 )
        {
            gettimeofday( &tv3, NULL );
            update_rx_quality( );
            if(G.s_iface != NULL)
            {
                check_monitor(wi, fd_raw, &fdh, G.num_cards);
                if(G.singlechan)
                    check_channel(wi, G.num_cards);
                if(G.singlefreq)
                    check_frequency(wi, G.num_cards);
            }
        }

        if(G.s_file != NULL)
        {
            /* Read one packet */
            n = sizeof( pkh );

            if( fread( &pkh, n, 1, G.f_cap_in ) != 1 )
            {
                memset(G.message, '\x00', sizeof(G.message));
                snprintf(G.message, sizeof(G.message), "][ Finished reading input file %s.\n", G.s_file);
                G.s_file = NULL;
                continue;
            }

            if( G.pfh_in.magic == TCPDUMP_CIGAM ) {
                SWAP32( pkh.caplen );
                SWAP32( pkh.len );
            }

            n = caplen = pkh.caplen;

            memset(buffer, 0, sizeof(buffer));
            h80211 = buffer;

            if( n <= 0 || n > (int) sizeof( buffer ) )
            {
                memset(G.message, '\x00', sizeof(G.message));
                snprintf(G.message, sizeof(G.message), "][ Finished reading input file %s.\n", G.s_file);
                G.s_file = NULL;
                continue;
            }

            if( fread( h80211, n, 1, G.f_cap_in ) != 1 )
            {
                memset(G.message, '\x00', sizeof(G.message));
                snprintf(G.message, sizeof(G.message), "][ Finished reading input file %s.\n", G.s_file);
                G.s_file = NULL;
                continue;
            }

            if( G.pfh_in.linktype == LINKTYPE_PRISM_HEADER )
            {
                if( h80211[7] == 0x40 )
                    n = 64;
                else
                    n = *(int *)( h80211 + 4 );

                if( n < 8 || n >= (int) caplen )
                    continue;

                memcpy( tmpbuf, h80211, caplen );
                caplen -= n;
                memcpy( h80211, tmpbuf + n, caplen );
            }

            if( G.pfh_in.linktype == LINKTYPE_RADIOTAP_HDR )
            {
                /* remove the radiotap header */

                n = *(unsigned short *)( h80211 + 2 );

                if( n <= 0 || n >= (int) caplen )
                    continue;

                memcpy( tmpbuf, h80211, caplen );
                caplen -= n;
                memcpy( h80211, tmpbuf + n, caplen );
            }

            if( G.pfh_in.linktype == LINKTYPE_PPI_HDR )
            {
                /* remove the PPI header */

                n = le16_to_cpu(*(unsigned short *)( h80211 + 2));

                if( n <= 0 || n>= (int) caplen )
                    continue;

                /* for a while Kismet logged broken PPI headers */
                if ( n == 24 && le16_to_cpu(*(unsigned short *)(h80211 + 8)) == 2 )
                    n = 32;

                if( n <= 0 || n>= (int) caplen )
                    continue;

                memcpy( tmpbuf, h80211, caplen );
                caplen -= n;
                memcpy( h80211, tmpbuf + n, caplen );
            }

            read_pkts++;

            if(read_pkts%10 == 0)
                usleep(1);
        }
        else if(G.s_iface != NULL)
        {
            /* capture one packet */

            FD_ZERO( &rfds );
            for(i=0; i<G.num_cards; i++)
            {
                FD_SET( fd_raw[i], &rfds );
            }

            tv0.tv_sec  = G.update_s;
            tv0.tv_usec = (G.update_s == 0) ? REFRESH_RATE : 0;

            gettimeofday( &tv1, NULL );

            if( select( fdh + 1, &rfds, NULL, NULL, &tv0 ) < 0 )
            {
                if( errno == EINTR )
                {
                    gettimeofday( &tv2, NULL );

                    time_slept += 1000000UL * ( tv2.tv_sec  - tv1.tv_sec  )
                                        + ( tv2.tv_usec - tv1.tv_usec );

                    continue;
                }
                perror( "select failed" );

                /* Restore terminal */
                fprintf( stderr, "\33[?25h" );
                fflush( stdout );

                return( 1 );
            }
        }
        else
            usleep(1);

        gettimeofday( &tv2, NULL );

        time_slept += 1000000UL * ( tv2.tv_sec  - tv1.tv_sec  )
                              + ( tv2.tv_usec - tv1.tv_usec );

        if( time_slept > REFRESH_RATE && time_slept > G.update_s * 1000000)
        {
            time_slept = 0;

            update_dataps();

            /* update the window size */

            if( ioctl( 0, TIOCGWINSZ, &(G.ws) ) < 0 )
            {
                G.ws.ws_row = 25;
                G.ws.ws_col = 80;
            }

            if( G.ws.ws_col <   1 ) G.ws.ws_col =   1;
            if( G.ws.ws_col > 300 ) G.ws.ws_col = 300;

            /* display the list of access points we have */

	    if(!G.do_pause) {
		pthread_mutex_lock( &(G.mx_print) );

		    fprintf( stderr, "\33[1;1H" );
		    dump_print( G.ws.ws_row, G.ws.ws_col, G.num_cards );
		    fprintf( stderr, "\33[J" );
		    fflush( stdout );

		pthread_mutex_unlock( &(G.mx_print) );
	    }
            continue;
        }

        if(G.s_file == NULL && G.s_iface != NULL)
        {
            fd_is_set = 0;

            for(i=0; i<G.num_cards; i++)
            {
                if( FD_ISSET( fd_raw[i], &rfds ) )
                {

                    memset(buffer, 0, sizeof(buffer));
                    h80211 = buffer;
                    if ((caplen = wi_read(wi[i], h80211, sizeof(buffer), &ri)) == -1) {
                        wi_read_failed++;
                        if(wi_read_failed > 1)
                        {
                            G.do_exit = 1;
                            break;
                        }
                        memset(G.message, '\x00', sizeof(G.message));
                        snprintf(G.message, sizeof(G.message), "][ interface %s down ", wi_get_ifname(wi[i]));

                        //reopen in monitor mode

                        strncpy(ifnam, wi_get_ifname(wi[i]), sizeof(ifnam)-1);
                        ifnam[sizeof(ifnam)-1] = 0;

                        wi_close(wi[i]);
                        wi[i] = wi_open(ifnam);
                        if (!wi[i]) {
                            printf("Can't reopen %s\n", ifnam);

                            /* Restore terminal */
                            fprintf( stderr, "\33[?25h" );
                            fflush( stdout );

                            exit(1);
                        }

                        fd_raw[i] = wi_fd(wi[i]);
                        if (fd_raw[i] > fdh)
                            fdh = fd_raw[i];

                        break;
//                         return 1;
                    }

                    read_pkts++;

                    wi_read_failed = 0;
                    dump_add_packet( h80211, caplen, &ri, i );
                }
            }
        }
        else if (G.s_file != NULL)
        {
            dump_add_packet( h80211, caplen, &ri, i );
        }
    }

    if(G.batt)
        free(G.batt);

    if(G.elapsed_time)
        free(G.elapsed_time);

    if(G.own_channels)
        free(G.own_channels);

    if(G.f_essid)
        free(G.f_essid);

    if(G.prefix)
        free(G.prefix);

    if(G.f_cap_name)
        free(G.f_cap_name);

    if(G.keyout)
        free(G.keyout);

#ifdef HAVE_PCRE
    if(G.f_essid_regex)
        pcre_free(G.f_essid_regex);
#endif

    for(i=0; i<G.num_cards; i++)
        wi_close(wi[i]);

    if (G.record_data) {
        if ( G. output_format_csv)  dump_write_csv();
        if ( G.output_format_kismet_csv) dump_write_kismet_csv();
        if ( G.output_format_kismet_netxml) dump_write_kismet_netxml();

        if ( G. output_format_csv || G.f_txt != NULL ) fclose( G.f_txt );
        if ( G.output_format_kismet_csv || G.f_kis != NULL ) fclose( G.f_kis );
        if ( G.output_format_kismet_netxml || G.f_kis_xml != NULL )
        {
			fclose( G.f_kis_xml );
			free(G.airodump_start_time);
		}
        if ( G.f_gps != NULL ) fclose( G.f_gps );
        if ( G.output_format_pcap ||  G.f_cap != NULL ) fclose( G.f_cap );
        if ( G.f_ivs != NULL ) fclose( G.f_ivs );
    }

    if( ! G.save_gps )
    {
        snprintf( (char *) buffer, 4096, "%s-%02d.gps", argv[2], G.f_index );
        unlink(  (char *) buffer );
    }

    ap_prv = NULL;
    ap_cur = G.ap_1st;

    while( ap_cur != NULL )
    {
		// Clean content of ap_cur list (first element: G.ap_1st)
        uniqueiv_wipe( ap_cur->uiv_root );

        list_tail_free(&(ap_cur->packets));

	if (G.manufList)
		free(ap_cur->manuf);

	if (G.detect_anomaly)
        	data_wipe(ap_cur->data_root);

        ap_prv = ap_cur;
        ap_cur = ap_cur->next;
    }

    ap_cur = G.ap_1st;

    while( ap_cur != NULL )
    {
		// Freeing AP List
        ap_next = ap_cur->next;

        if( ap_cur != NULL )
            free(ap_cur);

        ap_cur = ap_next;
    }

    st_cur = G.st_1st;
    st_next= NULL;

    while(st_cur != NULL)
    {
        st_next = st_cur->next;
	if (G.manufList)
		free(st_cur->manuf);
        free(st_cur);
        st_cur = st_next;
    }

    na_cur = G.na_1st;
    na_next= NULL;

    while(na_cur != NULL)
    {
        na_next = na_cur->next;
        free(na_cur);
        na_cur = na_next;
    }

    if (G.manufList) {
        oui_cur = G.manufList;
        while (oui_cur != NULL) {
            oui_next = oui_cur->next;
	    free(oui_cur);
	    oui_cur = oui_next;
        }
    }

    fprintf( stderr, "\33[?25h" );
    fflush( stdout );

    return( 0 );
}
