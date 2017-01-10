/*
 *  WEP Cloaking filtering
 *
 *  Copyright (C) 2008-2017 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
 *
 *  Thanks to Alex Hernandez aka alt3kx for the hardware.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include "airdecloak-ng.h"
#include "version.h"
#include "osdep/radiotap/radiotap_iter.h"

unsigned char buffer[65536];

char * _essid;

char * _filename_output_invalid;
char * _filename_output_cloaked;
char * _filename_output_filtered;
FILE * _output_cloaked_packets_file;
FILE * _output_clean_capture_file;
FILE * _input_file;
struct pcap_file_header _pfh_in;
struct pcap_file_header _pfh_out;

long _filters;

int _is_wep;

unsigned char _bssid[6];


int _options_drop_fragments = 0;
int _options_disable_retry = 0;
int _options_disable_base_filter = 0;
int _options_assume_null_packets_uncloaked = 0;

struct decloak_stats stats;

int getBits(unsigned char b, int from, int nb_bits)
{
	unsigned int value = (unsigned int)b;
	unsigned int and_1st = 0;
	int i;
	if (from < 0 || from > 7 || nb_bits <= 0 || (from + nb_bits) > 8)
	{
		return -1;
	}

	for (i = from; i < from + nb_bits; i++) {
		and_1st += 1 << i;
	}

	value &= and_1st;

	value >>= from;

	return value;
}


FILE * openfile(const char * filename, const char * mode, int fatal)
{
	FILE * f;

	if( ( f = fopen( filename, mode ) ) == NULL )
	{
	    perror( "fopen failed\n" );
	    printf( "Could not open \"%s\" in \"%s\" mode.\n", filename, mode );

	    if (fatal) {
			exit(1);
		}
    }

    return f;
}


// Return 1 on success, 0 on failure
BOOLEAN write_packet(FILE * file, struct packet_elt * packet)
{
	// TODO: Do not forget to swap what has to be swapped if needed (caplen, ...)
	int result;
	unsigned int caplen = packet->header.caplen;

	// Write packet header
	if( _pfh_in.magic == TCPDUMP_CIGAM )
		SWAP32( packet->header.caplen ); // Make sure it is re-swapped CORRECTLY -> OK

	result = fwrite(&(packet->header), 1, PACKET_HEADER_SIZE, file);
	if (result != PACKET_HEADER_SIZE)
	{
		perror("fwrite(packet header) failed");
		return false;
	}

	// Write packet
	result = fwrite(packet->packet, 1, caplen, file);
	if (result != (int)caplen)
	{
		perror("fwrite(packet) failed");
		return false;
	}

	return true;
}


FILE * init_new_pcap(const char * filename)
{
	FILE * f;

	f = openfile(filename, "wb", 1);

	if (f != NULL) {
		if( fwrite( &_pfh_out, 1, sizeof( _pfh_out ), f ) !=
					(size_t) sizeof( _pfh_out ) )
		{
			perror( "fwrite(pcap file header) failed" );
		}
	}


	return f;
}

FILE * open_existing_pcap(const char * filename) {
	FILE * f;
	size_t temp_sizet;

	f = fopen(filename, "rb");

    if( f == NULL )
    {
        perror( "Unable to open pcap" );
        return NULL;
    }

    temp_sizet = (size_t) sizeof( _pfh_in );

    if( fread( &_pfh_in, 1, temp_sizet, f ) !=  temp_sizet )
    {
        perror( "fread(pcap file header) failed" );
        fclose(f);
        return NULL;
    }

    if( _pfh_in.magic != TCPDUMP_MAGIC &&
        _pfh_in.magic != TCPDUMP_CIGAM )
    {
        printf( "\"%s\" isn't a pcap file (expected "
                "TCPDUMP_MAGIC).\n", filename );
        fclose(f);
        return NULL;
    }
    _pfh_out = _pfh_in;

    if( _pfh_in.magic == TCPDUMP_CIGAM )
    	SWAP32( _pfh_in.linktype );

    if( _pfh_in.linktype != LINKTYPE_IEEE802_11 &&
        _pfh_in.linktype != LINKTYPE_PRISM_HEADER &&
        _pfh_in.linktype != LINKTYPE_RADIOTAP_HDR &&
        _pfh_in.linktype != LINKTYPE_PPI_HDR )
    {
        printf( "\"%s\" isn't a regular 802.11 "
                "(wireless) capture.\n", filename );
        fclose(f);
        return NULL;
    }
    else if (_pfh_in.linktype == LINKTYPE_RADIOTAP_HDR)
    {
		printf("Radiotap header found. Parsing Radiotap is experimental.\n");
	}
    else if (_pfh_in.linktype == LINKTYPE_PPI_HDR)
    {
		printf("PPI not yet supported\n");
		fclose(f);
        return NULL;
	}


    //_pcap_linktype = _pfh_in.linktype;

	return f;
}

BOOLEAN initialize_linked_list() {
	_packet_elt_head = (struct packet_elt_header *)malloc(sizeof(struct packet_elt_header));
	_packet_elt_head->first = (	struct packet_elt *) malloc(sizeof(struct packet_elt));
	_packet_elt_head->last = _packet_elt_head->first;
	_packet_elt_head->current = _packet_elt_head->first;
	_packet_elt_head->current->complete = 0;
	_packet_elt_head->current->prev = NULL; // First packet, no previous
	_packet_elt_head->current->next = NULL;
	_packet_elt_head->nb_packets = 1;
	return true;
}

BOOLEAN add_node_if_not_complete() {
	if (_packet_elt_head->current->complete == 1) {
		// Allocate new packet
		_packet_elt_head->current->next = (struct packet_elt *) malloc(sizeof(struct packet_elt));
		_packet_elt_head->current->next->prev = _packet_elt_head->current;
		_packet_elt_head->current = _packet_elt_head->current->next;

		_packet_elt_head->current->complete = 0;
		_packet_elt_head->nb_packets +=1;

		// Last will be set at the end of the while when everything went ok
	} // No free of the *packet pointer because it is only set when everything is ok => if a packet is not ok, it will never have *packet malloced
	// Alway reset is_cloaked field and dropped field
	_packet_elt_head->current->is_cloaked = UKNOWN_FRAME_CLOAKING_STATUS; // Unknown state of this packet
	_packet_elt_head->current->is_dropped = 0;
	return true;
}

void set_node_complete() {
	_packet_elt_head->current->complete = 1;
	_packet_elt_head->last = _packet_elt_head->current;
}

void remove_last_uncomplete_node() {
	struct packet_elt * packet;
	if (_packet_elt_head->current->complete == 0) {
		packet = _packet_elt_head->current;
		_packet_elt_head->nb_packets -=1;
		_packet_elt_head->current->prev->next = NULL;
		free(packet);
	}
}

// Requirement: initialize_linked_list() called
struct packet_elt * getPacketNr(int position) {
	struct packet_elt * packet = _packet_elt_head->first;
	int i = 0;
	while (i < position) {
		if (packet->next == NULL) {
			return NULL;
		}
		packet = packet->next;
	}
	return packet;
}

char * iv2string(unsigned char * iv) {
	char * string = (char *)malloc(9);
	snprintf(string, 9, "%02X %02X %02X", iv[0], iv[1], iv[2]);
	return string;
}

char * icv2string(unsigned char * icv) {
	char * string = (char *)malloc(12);
	snprintf(string, 12, "%02X %02X %02X %02X", icv[0], icv[1], icv[2], icv[3]);
	return string;
}

void print_packet(struct packet_elt * packet) {
	char * temp;
	printf("Packet length: %d\n", packet->length);
	printf("Frame type: %d (subtype: %d) - First byte: %d\n", packet->frame_type, packet->frame_subtype, packet->version_type_subtype);
	temp = mac2string(packet->bssid);
	printf("BSSID: %s\n",temp);
	free(temp);
	temp = mac2string(packet->source);
	printf("Source: %s\n",temp);
	free(temp);
	temp = mac2string(packet->destination);
	printf("Destination: %s\n",temp);
	free(temp);
	printf("Sequence number: %d (Fragment #: %d)\n", packet->sequence_number, packet->fragment_number);
	temp = iv2string(packet->iv);
	printf("IV: %s (Key index: %d)\n", temp, packet->key_index);
	free(temp);
	temp = icv2string(packet->icv);
	printf("ICV: %s\n", temp);
	free(temp);

	printf("Signal: %d - Retry bit: %d - is cloaked: %d\n", packet->signal_quality, packet->retry_bit, packet->is_cloaked);
}

int get_rtap_signal(int caplen)
{
	struct ieee80211_radiotap_iterator iterator;
	struct ieee80211_radiotap_header *rthdr;

	rthdr = (struct ieee80211_radiotap_header *)buffer;

	if (ieee80211_radiotap_iterator_init(&iterator, rthdr, caplen, NULL) < 0)
	return 0;

	while (ieee80211_radiotap_iterator_next(&iterator) >= 0) {
		if (iterator.this_arg_index == IEEE80211_RADIOTAP_DBM_ANTSIGNAL)
			return *iterator.this_arg;
		if (iterator.this_arg_index == IEEE80211_RADIOTAP_DB_ANTSIGNAL)
			return *iterator.this_arg;
		if (iterator.this_arg_index == IEEE80211_RADIOTAP_LOCK_QUALITY)
			return *iterator.this_arg;
	}
	return 0;
}

// !!!! WDS not yet implemented
BOOLEAN read_packets(void)
{
	int i, start;
    time_t tt;
    unsigned char * h80211;
	size_t bytes_read;

	i=0;

	memset( &stats, 0, sizeof( stats ) );
	tt = time( NULL );

	switch(_pfh_in.linktype)
	{
		case LINKTYPE_PRISM_HEADER:
			start = 144; // based on madwifi-ng
			break;
		case LINKTYPE_RADIOTAP_HDR:
			start = (int)(buffer[2]); // variable length!
			break;
		case LINKTYPE_IEEE802_11:
			// 0
		case LINKTYPE_PPI_HDR:
			// ?
		default:
			start = 0;
			break;
	}

	// Show link type
	printf("Link type (Prism: %d - Radiotap: %d - 80211: %d - PPI - %d): ",
			LINKTYPE_PRISM_HEADER, LINKTYPE_RADIOTAP_HDR,
			LINKTYPE_IEEE802_11, LINKTYPE_PPI_HDR);

	switch (_pfh_in.linktype) {
		case LINKTYPE_PRISM_HEADER:
			puts("Prism");
			break;
		case LINKTYPE_RADIOTAP_HDR:
			puts("Radiotap");
			break;
		case LINKTYPE_IEEE802_11:
			puts("802.11");
			break;
		case LINKTYPE_PPI_HDR:
			puts("PPI");
			break;
		default:
			printf("Unknown (%lu)\n", (unsigned long) _pfh_in.linktype);
			break;
	}

	// Initialize double linked list.
	initialize_linked_list();

    while( 1 )
    {
        if( time( NULL ) - tt > 0 )
        {
            // update the status line every second

            printf( "\33[KRead %lu packets...\r", stats.nb_read );
            fflush( stdout );
            tt = time( NULL );
        }


        /* read one packet */

        // Only malloc if complete
		add_node_if_not_complete();

		//puts("Reading packet header");
		bytes_read = fread( &( _packet_elt_head->current->header ), 1, PACKET_HEADER_SIZE, _input_file );
        if( bytes_read != (size_t) PACKET_HEADER_SIZE )
        {
			if (bytes_read != 0) {
				printf("Failed to read packet header.\n");
			}
			else {
				// Normal, reached EOF.
				//printf("Reached EOF.\n");
			}
            break;
		}

        if( _pfh_in.magic == TCPDUMP_CIGAM )
            SWAP32( _packet_elt_head->current->header.caplen );


        if( _packet_elt_head->current->header.caplen <= 0 || _packet_elt_head->current->header.caplen > 65535 )
        {
            printf( "Corrupted file? Invalid packet length %lu.\n", (unsigned long) _packet_elt_head->current->header.caplen );
            break;
        }

        // Reset buffer
		memset(buffer, 0, 65536);

		// Read packet from file
		bytes_read = fread( buffer, 1, _packet_elt_head->current->header.caplen, _input_file );


        if( bytes_read != (size_t) _packet_elt_head->current->header.caplen )
        {
			printf("Error reading the file: read %lu bytes out of %lu.\n",
						(unsigned long) bytes_read,
						(unsigned long) _packet_elt_head->current->header.caplen);

            break;
		}

        stats.nb_read++;

		// Put all stuff in the packet header and

		// ---------------------------- Don't remove anything ----------------------
		// ---------------------------- Just know where the packet start -----------

        h80211 = buffer + start;

		// Know the kind of packet
		_packet_elt_head->current->frame_type = getBits(*h80211, 2, 2);

		#ifdef DEBUG
		printf("Frame type: %d\n", _packet_elt_head->current->frame_type);
		#endif

		_packet_elt_head->current->version_type_subtype = *h80211;

		#ifdef DEBUG
		printf("First byte: %x\n",*h80211);
		#endif

		// Filter out unknown packet types and control frames
		if (_packet_elt_head->current->frame_type != FRAME_TYPE_DATA &&
			_packet_elt_head->current->frame_type != FRAME_TYPE_MANAGEMENT) {
			// Don't care about the frame if it's a control or unknown frame).
			if (_packet_elt_head->current->frame_type != FRAME_TYPE_CONTROL) {
				// Unknown frame type, log it
				//printf("Unknown frame type: %d\n", packet->frame_type);
				// ------------- May be interesting to put all those packets in a separate file
			}
			continue;

		}

		if (_packet_elt_head->current->frame_type == FRAME_TYPE_MANAGEMENT) {
			// Assumption: Management packets are not cloaked (may change in the future)
			_packet_elt_head->current->is_cloaked = VALID_FRAME_UNCLOAKED;
		} else if (_packet_elt_head->current->frame_type == FRAME_TYPE_DATA){
			_packet_elt_head->current->is_cloaked = UKNOWN_FRAME_CLOAKING_STATUS;
		}

		// Retry bit
		_packet_elt_head->current->retry_bit = getBit(*(h80211+1), 3);

		// More fragments bit
		_packet_elt_head->current->more_fragments_bit = getBit(*(h80211+1), 2);
		if (_packet_elt_head->current->more_fragments_bit && _options_drop_fragments) {
			_packet_elt_head->current->is_dropped = 1;
		}

		// TODO: Get the speed from the packet if radiotap/prism header exist.

		// TODO: Get also the channel from the headers (the sensor may inject
		//       cloaked frames on a channel is not the same as the AP)


		#ifdef DEBUG
			printf("Retry bit: %d\n", _packet_elt_head->current->retry_bit);
			printf("More fragments bit: %d\n", _packet_elt_head->current->more_fragments_bit);
		#endif
        /*------------------------------- drop if control frame (does not contains SN) ----------------------*/
		// TODO: We should care about control frames since they are not cloaked
		//       and they can be usefull for signal filtering (have a better average).

        /* check the BSSID */
        switch( h80211[1] & 3 )
		{
			case  0:    // To DS = 0, From DS = 0: DA, SA, BSSID (Ad Hoc)
				memcpy( _packet_elt_head->current->destination, h80211 + 4, 6 );
				memcpy( _packet_elt_head->current->source, h80211 + 10, 6 );
				memcpy( _packet_elt_head->current->bssid, h80211 + 16, 6 );

				_packet_elt_head->current->fromDS = 0;
				_packet_elt_head->current->toDS = 0;
				break;

			case  1:    // To DS = 1, From DS = 0: BSSID, SA, DA (To DS)
				memcpy( _packet_elt_head->current->bssid, h80211 +  4, 6 );
				memcpy( _packet_elt_head->current->source, h80211 +  10, 6 );
				memcpy( _packet_elt_head->current->destination, h80211 +  16, 6 );

				_packet_elt_head->current->fromDS = 0;
				_packet_elt_head->current->toDS = 1;
				break;

			case  2:    // To DS = 0, From DS = 1: DA, BSSID, SA (From DS)
				memcpy( _packet_elt_head->current->destination, h80211 + 4, 6 );
				memcpy( _packet_elt_head->current->bssid, h80211 + 10, 6 );
				memcpy( _packet_elt_head->current->source, h80211 + 16, 6 );

				_packet_elt_head->current->fromDS = 1;
				_packet_elt_head->current->toDS = 0;
				break;

			case  3:    // To DS = 1, From DS = 1: RA, TA, DA, SA (WDS)
				memcpy( _packet_elt_head->current->source, h80211 + 24, 6 );
				memcpy( _packet_elt_head->current->bssid, h80211 + 10, 6 );
				memcpy( _packet_elt_head->current->destination, h80211 + 16, 6 );

				_packet_elt_head->current->fromDS = 1;
				_packet_elt_head->current->toDS = 1;
				break;
        }

		#ifdef DEBUG
        printf("From DS: %d - ToDS: %d\n", _packet_elt_head->current->fromDS, _packet_elt_head->current->toDS);
        printf("BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n", _packet_elt_head->current->bssid[0],
				_packet_elt_head->current->bssid[1], _packet_elt_head->current->bssid[2],
				_packet_elt_head->current->bssid[3], _packet_elt_head->current->bssid[4],
				_packet_elt_head->current->bssid[5]);
        printf("Source: %02X:%02X:%02X:%02X:%02X:%02X\n", _packet_elt_head->current->source[0],
				_packet_elt_head->current->source[1], _packet_elt_head->current->source[2], _packet_elt_head->current->source[3],
				_packet_elt_head->current->source[4], _packet_elt_head->current->source[5]);
        printf("Dest: %02X:%02X:%02X:%02X:%02X:%02X\n", _packet_elt_head->current->destination[0],
				_packet_elt_head->current->destination[1], _packet_elt_head->current->destination[2], _packet_elt_head->current->destination[3],
				_packet_elt_head->current->destination[4], _packet_elt_head->current->destination[5]);
		#endif

		// Filter out packets not belonging to our BSSID
		if (  memcmp( _packet_elt_head->current->bssid, _bssid, 6)) {
			// Not the BSSID we are looking for
			//printf("It's not the BSSID we are looking for.\n");
			continue;
		}

		// Grab sequence number and fragment number
		_packet_elt_head->current->sequence_number = ((h80211[22]>>4)+(h80211[23]<<4)); // 12 bits
		_packet_elt_head->current->fragment_number = getBits(h80211[23], 4,4); // 4 bits

		// drop frag option
		if (_options_drop_fragments
			&& _packet_elt_head->current->fragment_number) {
			_packet_elt_head->current->is_dropped = 1;
		}

		#ifdef DEBUG
		printf("Sequence: %d - Fragment: %d\n",
				_packet_elt_head->current->sequence_number,
				_packet_elt_head->current->fragment_number);
		#endif
		// Get the first beacon and search for WEP only
		// if not (data) wep, stop completely processing (_is_wep)
		if (_packet_elt_head->current->frame_type == FRAME_TYPE_MANAGEMENT)
		{
			// Get encryption from beacon/probe response
			if( h80211[0] == BEACON_FRAME || h80211[0] == PROBE_RESPONSE )
			{
				if( ( h80211[34] & 0x10 ) >> 4 ) {
					_is_wep = 1;
					// Make sure it's not WPA

					// TODO: See airodump-ng around line 1500
				}
				else {
					// Completely stop processing
					printf("FATAL ERROR: The network is not WEP (byte 34: %d)\n.", h80211[34]);
					exit(1);
				}
			}
		}

		if (_packet_elt_head->current->frame_type == FRAME_TYPE_DATA) {
			// Copy IV
			memcpy(_packet_elt_head->current->iv, (h80211 + 24), 3);

			#ifdef DEBUG
			printf("IV: %X %X %X\n", _packet_elt_head->current->iv[0], _packet_elt_head->current->iv[1], _packet_elt_head->current->iv[2]);
			#endif

			// Copy key index
			_packet_elt_head->current->key_index = h80211[27];
			#ifdef DEBUG
			printf("Key index: %d\n", _packet_elt_head->current->key_index);
			#endif
			// Copy checksum
			memcpy(_packet_elt_head->current->icv, buffer + (_packet_elt_head->current->header.caplen) - 4, 4);
			#ifdef DEBUG
			printf("ICV: %X %X %X %X\n", _packet_elt_head->current->icv[0], _packet_elt_head->current->icv[1], _packet_elt_head->current->icv[2], _packet_elt_head->current->icv[3]);
			#endif
		}
		else { // Management packet (control packets were filtered out.
			_packet_elt_head->current->iv[0] = _packet_elt_head->current->iv[1] = _packet_elt_head->current->iv[2] = 0;
			_packet_elt_head->current->key_index = 0;
			_packet_elt_head->current->icv[0] = _packet_elt_head->current->icv[1] = _packet_elt_head->current->icv[2] = _packet_elt_head->current->icv[3] = 0;
			#ifdef DEBUG
			printf("Not a data packet thus no IV, no key index, no ICV\n");
			#endif
		}

		// Copy the packet itself
		_packet_elt_head->current->packet = (unsigned char *) malloc(_packet_elt_head->current->header.caplen);
		memcpy(_packet_elt_head->current->packet, buffer, _packet_elt_head->current->header.caplen);

		// Copy signal if exist
		_packet_elt_head->current->signal_quality = -1;
		if (_pfh_in.linktype == LINKTYPE_PRISM_HEADER) {
			// Hack: pos 0x44 (at least on madwifi-ng)
			_packet_elt_head->current->signal_quality = buffer[0x44];
		}
		else if (_pfh_in.linktype == LINKTYPE_RADIOTAP_HDR) {
			_packet_elt_head->current->signal_quality = get_rtap_signal(
				_packet_elt_head->current->header.caplen);
		}
		#ifdef DEBUG
		printf("Signal quality: %d\n", _packet_elt_head->current->signal_quality);
		#endif


		// Append to the list
		#ifdef ONLY_FIRST_PACKET
		puts("!!! Don't forget to append");

		break;
		#else
		set_node_complete();
		#endif
    }
    remove_last_uncomplete_node();

    printf("Nb packets: %d           \n", _packet_elt_head->nb_packets);

    return true;
}

void reset_current_packet_pointer() {
	_packet_elt_head->current = _packet_elt_head->first;
}

BOOLEAN reset_current_packet_pointer_to_ap_packet() {
	reset_current_packet_pointer();
	return next_packet_pointer_from_ap();
}

BOOLEAN reset_current_packet_pointer_to_client_packet() {
	reset_current_packet_pointer();
	return next_packet_pointer_from_client();
}

BOOLEAN next_packet_pointer_from_ap() {
	while (_packet_elt_head->current->toDS != 0) {
		if (next_packet_pointer() == false) {
			return false;
		}
	}
	if (_packet_elt_head->current->toDS == 0) {
		return true;
	}
	else {
		return false;
	}
}

BOOLEAN next_packet_pointer_from_client() {
	while (_packet_elt_head->current->toDS == 0) {
		if (next_packet_pointer() == false) {
			return false;
		}
	}
	if (_packet_elt_head->current->toDS == 1) {
		return true;
	}
	else {
		return false;
	}
}

BOOLEAN next_packet_pointer() {
	BOOLEAN success = false;
	// Go to next packet if not the last one
	if (_packet_elt_head->current != _packet_elt_head->last) {
		_packet_elt_head->current = _packet_elt_head->current->next;
		success = true;
	}

	return success;
}

BOOLEAN prev_packet_pointer() {
	BOOLEAN success = false;
	// Go to next packet if not the last one
	if (_packet_elt_head->current != _packet_elt_head->first) {
		_packet_elt_head->current = _packet_elt_head->current->prev;
		success = true;
	}

	return success;
}


int compare_SN_to_current_packet(struct packet_elt * packet) {
	if (_packet_elt_head->current->sequence_number > packet->sequence_number) {
		// Current packet SN is superior to packet SN
		return 1;
	} else if (_packet_elt_head->current->sequence_number < packet->sequence_number) {
		// Current packet SN is inferior to packet SN
		return -1;
	}

	// Identical
	return 0;
}

BOOLEAN current_packet_pointer_same_fromToDS_and_source(struct packet_elt * packet) {
	BOOLEAN success = false;

	if (_packet_elt_head->current->fromDS == packet->fromDS
		&& _packet_elt_head->current->toDS == packet->toDS) {
		if (packet->fromDS == 1 && packet->toDS ==0) {
			// Coming from the AP, no other check needed
			// (BSSID check already done when creating this list)
			success = true;
		}
		else {
			// Also check MAC source
			if (maccmp(packet->source, _packet_elt_head->current->source) == 0) {
				success = true;
			}
		}
	} else if (packet->fromDS == 0 && packet->toDS == 0) {
		// Beacons (and some other packets) coming from the AP (both from and toDS are 0).
		if (_packet_elt_head->current->fromDS == 1
			&& _packet_elt_head->current->toDS == 0) {
			success = true;
		}
	}

	return success;
}


BOOLEAN prev_packet_pointer_same_fromToDS_and_source(struct packet_elt * packet) {
	BOOLEAN success = false;

	while (success == false && prev_packet_pointer()) {
		success = current_packet_pointer_same_fromToDS_and_source(packet);
	}
	return success;
}

BOOLEAN next_packet_pointer_same_fromToDS_and_source(struct packet_elt * packet) {
	BOOLEAN success = false;

	// !!! Now we only have the packets from the BSSID.

	while (success == 0 && next_packet_pointer()) {
		success = current_packet_pointer_same_fromToDS_and_source(packet);
	}
	return success;
}

BOOLEAN prev_packet_pointer_same_fromToDS_and_source_as_current() {
	return prev_packet_pointer_same_fromToDS_and_source(_packet_elt_head->current);
}

BOOLEAN next_packet_pointer_same_fromToDS_and_source_as_current() {
	return next_packet_pointer_same_fromToDS_and_source(_packet_elt_head->current);
}

int CFC_with_valid_packets_mark_others_with_identical_sn_cloaked() {
	// This filtered 1148 packets on a 300-350K capture (~150K were cloaked)
	// Filtering was done correctly, all packets marked as cloaked were really cloaked).
	struct packet_elt * current_packet;
	int how_far, nb_marked;

	puts("Cloaking - Marking all duplicate SN cloaked if frame is valid or uncloaked");

	// Start from the begining (useful comment)
	reset_current_packet_pointer();

	nb_marked = 0;
	do {
		// We should first check for each VALID_FRAME_UNCLOAKED or CLOAKED_FRAME packet
		// PACKET_CHECKING_LENGTH packets later (ONLY NEXT PACKETS)
		// and if one of the packet has an identical SN, mark it as CLOAKED
		if (_packet_elt_head->current->is_cloaked != VALID_FRAME_UNCLOAKED
			&& _packet_elt_head->current->is_cloaked != CLOAKED_FRAME) {
			// Go to next packet if frame is not valid
			continue;
		}

		current_packet = _packet_elt_head->current;

		//printf("Trying current packet: %d,%d (SN: %d)\n", current_packet->fromDS, current_packet->toDS, current_packet->sequence_number);

		//print_packet(_packet_elt_head->current);

		how_far = 0;
		while (++how_far <= PACKET_CHECKING_LENGTH &&
				next_packet_pointer_same_fromToDS_and_source(current_packet) == true ) {
			switch (_packet_elt_head->current->is_cloaked) {
				case VALID_FRAME_UNCLOAKED:
				case CLOAKED_FRAME:
					// Status known, so go to next frame
					break;
				case POTENTIALLY_CLOAKED_FRAME:
					//puts("CFC_with_valid_packets_mark_others_cloaked() - Invalid frame status found: POTENTIALLY_CLOAKED_FRAME");
					break; // Should never happen here
				case UKNOWN_FRAME_CLOAKING_STATUS:
					//printf("Found unknown cloaking status frame, checking it - tested: %d,%d (SN: %d)\n",
					//		_packet_elt_head->current->fromDS, _packet_elt_head->current->toDS, _packet_elt_head->current->sequence_number);
					if (compare_SN_to_current_packet(current_packet) == 0) {
						_packet_elt_head->current->is_cloaked = CLOAKED_FRAME;
						++nb_marked;
					}
					break;
			}
		}

		// Go back to the current packet
		_packet_elt_head->current = current_packet;

	} while (next_packet_pointer() == 1);

	// Reset packet pointer so that next usages of current packet
	// will start from the begining (in case it's forgotten).
	reset_current_packet_pointer();

	printf("%d frames marked\n", nb_marked);

	return nb_marked;
}

int CFC_filter_duplicate_sn_ap() {
	int nb_packets = 0;
	puts("Cloaking - Removing the duplicate SN for the AP");

	reset_current_packet_pointer();

	return nb_packets;
}

int CFC_filter_duplicate_sn_client() {
	int nb_packets = 0;
	puts("Cloaking - Removing the duplicate SN for the client");

	reset_current_packet_pointer();

	return nb_packets;
}

int CFC_filter_duplicate_sn() {
	// This will remove a lot of legitimate packets unfortunatly
	return CFC_filter_duplicate_sn_ap() + CFC_filter_duplicate_sn_client();
}

int get_average_signal_ap() {
	long all_signals;
	long nb_packet_used;
	int average_signal;

	// Init
	all_signals = nb_packet_used = 0;
	average_signal = -1;

	// Check if signal quality is included
	if (_pfh_in.linktype == LINKTYPE_PRISM_HEADER
		|| _pfh_in.linktype == LINKTYPE_RADIOTAP_HDR) {

		if (reset_current_packet_pointer_to_ap_packet() == true) {

			// Calculate signal for all beacons and probe response (and count number of packets).
			do {
				if (_packet_elt_head->current->version_type_subtype == BEACON_FRAME
					|| _packet_elt_head->current->version_type_subtype == PROBE_RESPONSE) {
					++nb_packet_used;
					all_signals += _packet_elt_head->current->signal_quality;
				}
			}
			while (next_packet_pointer_same_fromToDS_and_source(_packet_elt_head->current) == true);

			// Calculate the average
			if (nb_packet_used > 0) {
				average_signal = (int)(all_signals / nb_packet_used);
				if ( ((all_signals/ (double)nb_packet_used) - average_signal) * 100 > 50) {
					++average_signal;
				}
			}
			printf("Average signal for AP packets: %d\n", average_signal);
		}
		else {
			puts("Average signal: No packets coming from the AP, cannot calculate it");
		}
	}
	else {
		puts("Average signal cannot be calculated because headers does not include it");
	}

	// Return
	return average_signal;
}

/**
 * Filter packets based on signal.
 *
 * Use signal from all beacons, make an average
 * This will allow to find out what packet are legitimate (coming from the AP) and thus removing cloaked packets
 * By being able to remove cloaked packets, we'll find out the signal of the sensor(s)
 * //and we'll be able to filter out the cloaked packets of clients.
 *
 * Enh: use signal from packets marked uncloaked instead of beacons.
 *
 * @return Number of frames marked cloaked.
 */
int CFC_filter_signal() {

	// Maximum variation of the signal for unknown status frame and potentially cloaked frames (up & down)
	#define MAX_SIGNAL_VARIATION 3
	#define MAX_SIGNAL_VARIATION_POTENTIALLY_CLOAKED 2


	int average_signal;
	int nb_packets = 0;
	puts("Cloaking - Signal filtering");

	// 1. Get the average signal
	average_signal = get_average_signal_ap();

	if (average_signal > 0) {

		reset_current_packet_pointer_to_ap_packet(); // Will be successful because signal > 0

		do {
			switch (_packet_elt_head->current->is_cloaked) {
				case POTENTIALLY_CLOAKED_FRAME:
					// Max allowed variation for potentially cloaked packet is a bit lower
					// than the normal variation
					if (abs(_packet_elt_head->current->signal_quality - average_signal)
							> MAX_SIGNAL_VARIATION_POTENTIALLY_CLOAKED) {
						_packet_elt_head->current->is_cloaked = CLOAKED_FRAME;
						++nb_packets;
						break;
					}
				case UKNOWN_FRAME_CLOAKING_STATUS:
					// If variation is > max allowed variation, it's a cloaked packet
					if (abs(_packet_elt_head->current->signal_quality - average_signal)
						> MAX_SIGNAL_VARIATION) {
						_packet_elt_head->current->is_cloaked = CLOAKED_FRAME;
						++nb_packets;
						break;
					}


					if (_packet_elt_head->current->signal_quality - average_signal == 0) {
						// If there's no variation, I'm sure it's not a cloaked packet
						_packet_elt_head->current->is_cloaked = VALID_FRAME_UNCLOAKED;
					}
					else {
						// We could play with POTENTIALLY_CLOAKED frame depending on the variation
						// but currently, it's unloacked if inferior to the max allowed signal
						_packet_elt_head->current->is_cloaked = VALID_FRAME_UNCLOAKED;
					}
					break;
				case VALID_FRAME_UNCLOAKED:
					break;
				case CLOAKED_FRAME:
					break;
				default:
					break;
			}
		} while (next_packet_pointer_same_fromToDS_and_source_as_current() == true);
	}

	// TODO: Do it also for clients: Calculate the average for know cloaked frames
	//       (each frame marked cloaked here) and then filter out wep cloaked frames.
	//        or implement it as another filter (since clients may have the same signal
	//        as the sensor).

	// Return
	return nb_packets;
}

int CFC_filter_consecutive_sn() {
	int nb_packets = 0;
	puts("Cloaking - Consecutive SN filtering");

	nb_packets = CFC_filter_consecutive_sn_ap() + CFC_filter_consecutive_sn_client();

	return nb_packets;
}

int CFC_filter_consecutive_sn_ap() {
	int nb_packets = 0;
	BOOLEAN next_packet_result = false;
	puts("Cloaking - Consecutive SN filtering (AP)");

	// Filtering for the client is not easy at all, maybe we can base on the fact that wep cloaking clone everything in the packet
	// except the data (and ofc the SN).

	// So, atm filtering for the AP only (hoping the client is not uploading data ;))

	reset_current_packet_pointer_to_ap_packet();

	// Go to the first beacon or probe response.
	while ( !(_packet_elt_head->current->version_type_subtype == BEACON_FRAME
			|| _packet_elt_head->current->version_type_subtype == PROBE_RESPONSE) ) {

		next_packet_result = next_packet_pointer_same_fromToDS_and_source_as_current();
		// Check if we didn't reach end of capture.
		if (next_packet_result == false) {
			break;
		}
	}

	// If end of capture, no packets have been filters.
	if (next_packet_result == false) {
		return 0;
	}


	puts("NYI");



	return nb_packets;
}

int CFC_filter_consecutive_sn_client() {
	int nb_packets = 0;

	puts("Cloaking - Consecutive SN filtering (Client)");

	// For consecutive SN of the client, if packets are cloaked, we can rely on null frames or probe request/association request.

	reset_current_packet_pointer_to_client_packet();

	// while

	puts("Not yet implemented");

	return nb_packets;
}

int CFC_filter_duplicate_iv() {
	unsigned char * ivs_table;
	int nb_packets = 0;
	puts("Cloaking - Duplicate IV filtering");

	ivs_table = (unsigned char *) calloc(16777215, 1);
	if (ivs_table == NULL) {
		puts("Failed to allocate memory for IVs table, exiting");
		exit(-1);
	}

	// 1. Get the list of all IV values (and number of duplicates
	reset_current_packet_pointer();
	do {
		if (_packet_elt_head->current->frame_type == FRAME_TYPE_DATA) {
			// In the array, there's as much elements as the number of possible IVs
			// For each IV, increase by 1 the value of the IV position so that we can
			// know if it was used AND the number of occurences.
			*(ivs_table + get_iv(_packet_elt_head->current)) += 1;
		}
	} while (next_packet_pointer() == true);

	// 2. Remove duplicates
	reset_current_packet_pointer();
	do {
		if (_packet_elt_head->current->frame_type == FRAME_TYPE_DATA) {

			switch (_packet_elt_head->current->is_cloaked) {
				case POTENTIALLY_CLOAKED_FRAME:
					// If the frame is potentially cloaked, mark it as cloaked
					if (*(ivs_table + get_iv(_packet_elt_head->current)) > 1) {
						_packet_elt_head->current->is_cloaked = CLOAKED_FRAME;
						++nb_packets;
					}
				case UKNOWN_FRAME_CLOAKING_STATUS:
					// If unknown status, mark it as potentially cloaked
					if (*(ivs_table + get_iv(_packet_elt_head->current)) > 1) {
						_packet_elt_head->current->is_cloaked = POTENTIALLY_CLOAKED_FRAME;
					}
					break;
				case VALID_FRAME_UNCLOAKED:
					break;
				case CLOAKED_FRAME:
					break;
				default:
					break;
			}

		}
	} while (next_packet_pointer() == true);

	free(ivs_table);

	return nb_packets;
}

char * status_format(int status) {
	size_t len = 19;
	char * ret = (char *) calloc(1, (len + 1) * sizeof(char));

	switch (status) {
		case VALID_FRAME_UNCLOAKED:
			strncpy(ret, "uncloacked", len);
			break;
		case CLOAKED_FRAME:
			strncpy(ret, "cloaked", len);
			break;
		case POTENTIALLY_CLOAKED_FRAME:
			strncpy(ret, "potentially cloaked", len);
			break;
		case UKNOWN_FRAME_CLOAKING_STATUS:
			strncpy(ret, "unknown cloaking", len);
			break;
		default:
			snprintf(ret, len + 1,"type %d", status);
			break;
	}

	ret = (char *)realloc(ret, strlen(ret) +1);
	return ret;
}

int CFC_mark_all_frames_with_status_to(int original_status, int new_status) {
	int nb_marked = 0;
	char * from, *to;
	from = status_format(original_status);
	to = status_format(new_status);

	printf("Cloaking - Marking all %s status frames as %s\n", from, to);
	free(from);
	free(to);

	reset_current_packet_pointer();

	do {
		if (_packet_elt_head->current->is_cloaked == original_status) {
			_packet_elt_head->current->is_cloaked = new_status;
			++nb_marked;
		}
	} while (next_packet_pointer() == 1);

	printf("%d frames marked\n", nb_marked);

	return nb_marked;
}


int CFC_filter_signal_duplicate_and_consecutive_sn() {
	int nb_marked = 0;
	// This filter does not call all other filters but does a lot of checks
	// and depending on these check decide if a packet is cloaked or not
	puts("Cloaking - Filtering all packet with signal, duplicate and consecutive SN filters");

	puts("Not yet implemented");

	return nb_marked;
}

// When checking do it on packet with the same direction (ToFroDS: 10 or 01)
// WDS/Ad hoc not implemented yet
/**
 * Check for cloaking and mark the status all packets (Cloaked or uncloaked).
 */
BOOLEAN check_for_cloaking() {
	int cur_filter;
	int cur_filters = _filters;

	puts("Cloaking - Start check");



	// Parse all packets, then for each packet marked valid (or cloaked), check forward if any packet has
	// an unknown status and same SN. If it's the case, mark the current packet CLOAKED
	if (_options_disable_base_filter == 0) {
		//CFC_with_valid_packets_mark_others_with_identical_sn_cloaked();
		CFC_base_filter();
	}

	// Apply all filter requested by the user in the requested order
	// but do not forget to warn when there's no filter given.
	while (cur_filters != 0) {
		cur_filter = cur_filters % 10;
		cur_filters /= 10;

		switch (cur_filter) {
			case FILTER_SIGNAL:
				CFC_filter_signal();
				break;
			case FILTER_DUPLICATE_SN:
				CFC_filter_duplicate_sn();
				break;
			case FILTER_DUPLICATE_SN_AP:
				CFC_filter_duplicate_sn_ap();
				break;
			case FILTER_DUPLICATE_SN_CLIENT:
				CFC_filter_duplicate_sn_client();
				break;
			case FILTER_CONSECUTIVE_SN:
				CFC_filter_consecutive_sn();
				break;
			case FILTER_DUPLICATE_IV:
				CFC_filter_duplicate_iv();
				break;
			case FILTER_SIGNAL_DUPLICATE_AND_CONSECUTIVE_SN:
				CFC_filter_signal_duplicate_and_consecutive_sn();
				break;
			case 0:
				puts("0 is not a valid filter number");
				exit(1);
			default:
				printf("Filter %d not yet implemented\n", cur_filter);
				exit(1);
		}
	}

	// Marking of all unknown status packets uncloaked (MUST BE AT THE END)
	CFC_mark_all_frames_with_status_to(UKNOWN_FRAME_CLOAKING_STATUS, VALID_FRAME_UNCLOAKED);
	// ... and the potentially cloaked cloaked
	CFC_mark_all_frames_with_status_to(POTENTIALLY_CLOAKED_FRAME, CLOAKED_FRAME);

	return true;
}

// Return 1 on success
BOOLEAN write_packets() {
	// Open files ...
	FILE * invalid_status_file;

	if (_filename_output_invalid != NULL)
		invalid_status_file = init_new_pcap(_filename_output_invalid);
	else
		invalid_status_file = init_new_pcap("invalid_status.pcap");

	_output_cloaked_packets_file = init_new_pcap(_filename_output_cloaked);
	_output_clean_capture_file = init_new_pcap(_filename_output_filtered);

	// ... and make sure opening was ok ...
	if (_output_clean_capture_file == NULL) {
		printf("FATAL ERROR: Failed to open pcap for filtered packets\n");
		if (_output_cloaked_packets_file != NULL) {
			fclose(_output_cloaked_packets_file);
		}
		return false;
	}

	// ... for both.
	if (_output_cloaked_packets_file == NULL) {
		printf("FATAL ERROR: Failed to open pcap for cloaked packets\n");
		fclose(_output_clean_capture_file);
		return false;
	}

	puts("Writing packets to files");

	reset_current_packet_pointer();
	do {
		switch (_packet_elt_head->current->is_cloaked) {
			case CLOAKED_FRAME:
				write_packet(_output_cloaked_packets_file, _packet_elt_head->current);
				break;
			case VALID_FRAME_UNCLOAKED:
				if (_packet_elt_head->current->is_dropped == 0) {
					write_packet(_output_clean_capture_file, _packet_elt_head->current);
				}
				break;
			default:
				// Write them somewhere else
				write_packet(invalid_status_file, _packet_elt_head->current);
				printf("Error: Invalid packet cloaking status: %d\n",
						_packet_elt_head->current->is_cloaked);
				break;

		}
	} while (next_packet_pointer() == true);

	puts("End writing packets to files");
	// Close files
	fclose(_output_cloaked_packets_file);
	fclose(_output_clean_capture_file);
	fclose(invalid_status_file);
	return true;
}

// Return 1 on success
BOOLEAN print_statistics() {
	return true;
}

void usage() {
	char *version_info = getVersion("Airdecloak-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC);
	printf("\n"
			"  %s - (C) 2008-2015 Thomas d\'Otreppe\n"
			"  http://www.aircrack-ng.org\n"
			"\n"
			"  usage: airdecloak-ng [options]\n"
			"\n"
			"  options:\n"
			"\n"
			"   Mandatory:\n"
			"     -i <file>             : Input capture file\n"
			"     --ssid <ESSID>        : ESSID of the network to filter\n"
			"        or\n"
			"     --bssid <BSSID>       : BSSID of the network to filter\n"
			"\n"
			"   Optional:\n"
			"     -o <file>             : Output packets (valid) file (default: <src>-filtered.pcap)\n"
			"     -c <file>             : Output packets (cloaked) file (default: <src>-cloaked.pcap)\n"
			"     -u <file>             : Output packets (unknown/ignored) file (default: invalid_status.pcap)\n"
			"     --filters <filters>   : Apply filters (separated by a comma). Filters:\n"
			"           signal:               Try to filter based on signal.\n"
			"           duplicate_sn:         Remove all duplicate sequence numbers\n"
			"                                 for both the AP and the client.\n"
			"           duplicate_sn_ap:      Remove duplicate sequence number for\n"
			"                                 the AP only.\n"
			"           duplicate_sn_client:  Remove duplicate sequence number for the\n"
			"                                 client only.\n"
			"           consecutive_sn:       Filter based on the fact that IV should\n"
			"                                 be consecutive (only for AP).\n"
			"           duplicate_iv:         Remove all duplicate IV.\n"
			"           signal_dup_consec_sn: Use signal (if available), duplicate and\n"
			"                                 consecutive sequence number (filtering is\n"
			"                                  much more precise than using all these\n"
			"                                  filters one by one).\n"
			"     --null-packets        : Assume that null packets can be cloaked.\n"
			"     --disable-base_filter : Do not apply base filter.\n"
			//"     --disable-retry       : Disable retry check, don't care about retry bit.\n"
			"     --drop-frag           : Drop fragmented packets\n"
			"\n"
			"     --help                : Displays this usage screen\n"
			"\n",
			version_info );
	free(version_info);
}

int main( int argc, char *argv[] )
{
    int temp = 0, option;
    int manual_cloaked_fname=0, manual_filtered_fname=0;
    BOOLEAN tempBool;
    char * input_filename;
    char * input_bssid;
    char * filter_name;

	// Initialize
	input_bssid = NULL;
	input_filename = NULL;
	_is_wep = -1;
	_output_cloaked_packets_file = NULL;
	_output_clean_capture_file = NULL;
	_input_file = NULL;
	memset(_bssid, 0, 6);
	_filters = 0;

    _filename_output_invalid = NULL;

	// Parse options
	while( 1 )
	{

        int option_index = 0;

        static struct option long_options[] = {
            {"essid",				1, 0, 'e'},
            {"ssid",				1, 0, 'e'},
            {"bssid",				1, 0, 'b'},
            {"help",				0, 0, 'h'},
            {"filter",				1, 0, 'f'},
            {"filters",				1, 0, 'f'},
            {"null-packets",		0, 0, 'n'},
            {"null-packet",			0, 0, 'n'},
            {"null_packets",		0, 0, 'n'},
            {"null_packet",			0, 0, 'n'},
            {"no-base-filter",		0, 0, 'a'},
            {"disable-base-filter",	0, 0, 'a'},
            //{"disable-retry",		0, 0, 'r'},
            {"drop-frag",			0, 0, 'd'},
            {"input",				1, 0, 'i'},
            {"cloaked",				1, 0, 'c'},
            {"filtered",			1, 0, 'f'},
            {0,						0, 0,  0 }
        };

		//option = getopt_long( argc, argv, "e:b:hf:nbrdi:",
		option = getopt_long( argc, argv, "e:b:hf:nbdi:c:o:u:",
                        long_options, &option_index );

		if( option < 0 ) break;


		switch( option )
		{
			case ':' :

				printf("\"%s --help\" for help.\n", argv[0]);
				return( 1 );

			case '?' :

				printf("\"%s --help\" for help.\n", argv[0]);
				return( 1 );
			case 'a':
				_options_disable_base_filter = 1;
				break;
			case 'i':
				input_filename = optarg;
				break;
			case 'c':
				if (optarg != NULL)
				{
					_filename_output_cloaked = optarg;
					manual_cloaked_fname = 1;
				}
				break;
			case 'o':
				if (optarg != NULL)
				{
    				_filename_output_filtered = optarg;
	    			manual_filtered_fname = 1;
    			}
				break;
			case 'u':
				if (optarg != NULL)
					_filename_output_invalid = optarg;
				break;
			case 'b':
				if (getmac(optarg, 1, _bssid)) {
					puts("Failed to parse MAC address");
					exit(1);
				}

				input_bssid = optarg;
				// make sure it was converted successfully
				break;
			case 'f':
				// Filters
				filter_name = strtok(optarg, ",");
				temp = 1;
				while (filter_name != NULL) {
					if (strcmp(filter_name, "signal") == 0
						|| atoi(filter_name) == FILTER_SIGNAL) {
						_filters = _filters + (FILTER_SIGNAL * temp);
					}
					else if (strcmp(filter_name, "duplicate_sn") == 0
						|| atoi(filter_name) == FILTER_DUPLICATE_SN) {
						_filters = _filters + (FILTER_DUPLICATE_SN * temp);
					}
					else if (strcmp(filter_name, "duplicate_sn_ap") == 0
						|| atoi(filter_name) == FILTER_DUPLICATE_SN_AP) {
						_filters = _filters + (FILTER_DUPLICATE_SN_AP * temp);
					}
					else if (strcmp(filter_name, "duplicate_sn_client") == 0
						|| atoi(filter_name) == FILTER_DUPLICATE_SN_CLIENT) {
						_filters = _filters + (FILTER_DUPLICATE_SN_CLIENT * temp);
					}
					else if (strcmp(filter_name, "consecutive_sn") == 0
						|| atoi(filter_name) == FILTER_CONSECUTIVE_SN) {
						_filters = _filters + (FILTER_CONSECUTIVE_SN * temp);
					}
					else if (strcmp(filter_name, "duplicate_iv") == 0
						|| atoi(filter_name) == FILTER_DUPLICATE_IV) {
						_filters = _filters + (FILTER_DUPLICATE_IV * temp);
					}
					else if (strcmp(filter_name, "signal_dup_consec_sn") == 0
						|| atoi(filter_name) == FILTER_SIGNAL_DUPLICATE_AND_CONSECUTIVE_SN) {
						_filters = _filters + (FILTER_SIGNAL_DUPLICATE_AND_CONSECUTIVE_SN * temp);
					}
					else {
						usage();
						puts("Invalid filter name");
						exit(1);
					}
					temp *= 10;
					filter_name = strtok(NULL, ",");
				}
				break;
			case 'd':
				_options_drop_fragments = 1;
				break;
			case 'n':
				_options_assume_null_packets_uncloaked = 1;
				break;
			case 'r':
				_options_disable_retry = 1;
				printf("'%c' option not yet implemented\n", option);
				exit(0);
				break;
			case 'e':
				printf("'%c' option not yet implemented\n", option);
				exit(0);
				break;
			case 'h':
				usage();
				exit(0);
				break;

		}

	}

	if (input_filename == NULL) {
		usage();
		puts("Missing input file");
		exit(1);
	}

	// Add options (some are mandatory, some are optional).
	/*
		Mandatory:
			-i file: input file
			--ssid ESSID (or --essid or --ssid) or -b BSSID (or --bssid or --ap)

		Optional:
			-o <file>             : Output packets (valid) file (default: <src>-filtered.pcap)
			-c <file>             : Output packets (cloaked) file (default: <src>-cloaked.pcap)
			-u <file>             : Output packets (unknown/ignored) file (default: invalid_status.pcap)
			-f (--filters/--filter)
				Available filters:
					* signal: Tries to filter based on the signal (AP never/is not supposed to moves thus ...)
					* duplicate_sn: remove all duplicate SN
					* duplicate_sn_ap/duplicate_sn_client: remove all duplicate SN from the AP/Client
					* consecutive_sn: filter based on the fact that IV should be consecutive (only for AP).
				Several filters can be used and you can choose the order of application of these filters
					(that will impact the results).
			--null-packets: Do not assume that null packets are not cloaked.
			--no-base_filter: do not apply base filter.
			--disable-retry: disable retry check, don't care about retry bit.
			--drop-frag: Drop fragmented packets
	*/

	printf("Input file: %s\n", input_filename);
	printf("BSSID: %s\n", input_bssid);
	puts("");


	// Open capture file
	puts("Opening file");
	_input_file = open_existing_pcap(input_filename);

	if (_input_file == NULL) {
		return 1;
	}

	// Create output filenames
	if (manual_cloaked_fname == 0 || manual_filtered_fname == 0)
	{
        temp = strlen( input_filename );
        if (!manual_cloaked_fname)
            _filename_output_cloaked = (char *) calloc(temp + 9 + 5, 1);

        if (!manual_filtered_fname)
            _filename_output_filtered = (char *) calloc(temp + 10 + 5, 1);

	while (--temp > 0)
	{
	    if (input_filename[temp] == '.')
		break;
	}

	    // No extension
        if (temp == 0) {
            if (!manual_cloaked_fname)
                snprintf(_filename_output_cloaked, strlen( input_filename ) + 9 + 5, "%s-cloaked.pcap", input_filename);
            if (!manual_filtered_fname)
                snprintf(_filename_output_filtered, strlen( input_filename ) + 10 + 5, "%s-filtered.pcap", input_filename);
        }
        else {
            if (!manual_cloaked_fname)
            {
                strncpy(_filename_output_cloaked, input_filename, strlen( input_filename ) + 9 + 5 - 1);
                strncat(_filename_output_cloaked, "-cloaked.pcap", 14);
            }
            if (!manual_filtered_fname)
            {
                strncpy(_filename_output_filtered, input_filename, strlen( input_filename ) + 10 + 5 - 1);
                strncat(_filename_output_filtered, "-filtered.pcap", 15);
            }
        }
    }

	printf("Output packets (valid) filename: %s\n",  _filename_output_filtered);
	printf("Output packets (cloaked) filename: %s\n",  _filename_output_cloaked);

	// 1. Read all packets and put the following in a linked list:
	//    Data and management packets only (filter out control packets)
	//    Packets where BSSID is the address given in parameter
	//    When we find a beacon, make sure the network is WEP

	puts("Reading packets from file");
	tempBool = read_packets();
	fclose(_input_file);

	if (tempBool != true) {
		printf("Failed reading packets: %d\n", temp);
		return 1;
	}



	// 2. Go thru the list and mark all cloaked packets
	puts("Checking for cloaked frames");
	tempBool = check_for_cloaking();
	if (tempBool != true) {
		printf("Checking for cloaking failed: %d\n", temp);
		return 1;
	}


	// 3. Write all data to output files

	// Write packets
	puts("Writing packets to files");
	tempBool = write_packets();
	if (tempBool != true) {
		printf("Writing packets failed: %d\n", temp);
		return 1;
	}

	// 4. Print some statistics
	// - Is the network using WEP?
	// - WEP cloaking in action?
	// - Clients MACs
	// - Number of data packets for the BSSID
	//   Number of good packets kept
	//   Number of cloaked packets removed
	// - File names
	print_statistics();

	return 0;
}
