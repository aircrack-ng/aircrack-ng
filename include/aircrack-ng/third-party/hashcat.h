/*
 *  Hashcat structures and macros
 *
 *  Copyright (C) 2018-2022 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
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

#ifndef _HASHCAT_H_
#define _HASHCAT_H_

#include <stdint.h>

// Hashcat v3.5 and lower
typedef struct
{
	char essid[36];

	unsigned char mac1[6];
	unsigned char mac2[6];
	unsigned char nonce1[32];
	unsigned char nonce2[32];

	unsigned char eapol[256];
	int eapol_size;

	int keyver;
	unsigned char keymic[16];

} hccap_t;

// Docs: https://hashcat.net/wiki/doku.php?id=hccapx

#define HCCAPX_SIGNATURE 0x58504348 // HCPX

#define HCCAPX_CURRENT_VERSION 4

// https://hashcat.net/wiki/doku.php?id=hccapx
typedef struct hccapx
{
	uint32_t
		signature; /* signature (file magic) of .hccapx files, it is always the
					  string HCPX */
	uint32_t version; /* version number of the .hccapx file format */
	uint8_t message_pair; /* possible values range from 0 to 5 or 128 to 133 */
	/* message_pair was extended with some additional information: the highest
   * bit could be used
   * to indicate if the message pair matching was done based on replay counter
   * or not. Whenever
   * the highest bit (bit 8) was set to 1 it means that the replay counter was
   * ignored (i.e. it
   * was not considered at all by the matching algorithm):
   *
   * .----------------------------------------------------------------------------------------------------------------------------.
   * | message_pair (hex) | message_pair (dec) | Highest bit | Meaning |
   * .----------------------------------------------------------------------------------------------------------------------------.
   * | 0x00 to 0x05       | 0 to 5             | 0           | Message pair
   * according to table below with replay counter matching |
   * | 0x80 to 0x85       | 128 to 133         | 1           | Message pair
   * according to table below, replay counter was ignored  |
   * .----------------------------------------------------------------------------------------------------------------------------.
   *
   * The message_pair value describes which messages of the 4-way handshake were
   * combined to form the
   * .hccapx structure. It is always a pair of 2 messages: 1 from the AP (access
   * point) and 1 from the STA (client).
   *
   * Furthermore, the message_pair value also gives a hint from which of the 2
   * messages the EAPOL origins.
   * This is interesting data, but not necessarily needed for hashcat to be able
   * to crack the hash.
   *
   * On the other hand, it could be very important to know if "only" message 1
   * and message 2 were captured
   * or if for instance message 3 and/or message 4 were captured too. If message
   * 3 and/or message 4 were captured
   * it should be a hard evidence that the connection was established and that
   * the password the client used was the
   * correct one.
   *
   * The following table lists all values currently allowed for the message_pair
   * field:
   *
   * .----------------------------------------------------------------------------------------------------------------------------.
   * | message_pair value | Messages of the handshake | Source of the EAPOL | AP
   * message | STA message | Replay counter matching  |
   * .----------------------------------------------------------------------------------------------------------------------------.
   * | 0                  | M1 + M2                   | M2                  | M1
   * | M2          | Yes                      |
   * | 1                  | M1 + M4                   | M4                  | M1
   * | M4          | Yes                      |
   * | 2                  | M2 + M3                   | M2                  | M3
   * | M2          | Yes                      |
   * | 3                  | M2 + M3                   | M3                  | M3
   * | M2          | Yes                      |
   * | 4                  | M3 + M4                   | M3                  | M3
   * | M4          | Yes                      |
   * | 5                  | M3 + M4                   | M4                  | M3
   * | M4          | Yes                      |
   * | 128                | M1 + M2                   | M2                  | M1
   * | M2          | No                       |
   * | 129                | M1 + M4                   | M4                  | M1
   * | M4          | No                       |
   * | 130                | M2 + M3                   | M2                  | M3
   * | M2          | No                       |
   * | 131                | M2 + M3                   | M3                  | M3
   * | M2          | No                       |
   * | 132                | M3 + M4                   | M3                  | M3
   * | M4          | No                       |
   * | 133                | M3 + M4                   | M4                  | M3
   * | M4          | No                       |
   * .----------------------------------------------------------------------------------------------------------------------------.
   *
   * Note: M1 means message 1 of the handshake, M2 means message 2 of the
   * handshake, M3 means message 3 of
   * the handshake and M4 means message 4 of the 4-way handshake
   */
	uint8_t essid_len; /* length of the network name (ESSID)  */
	uint8_t essid[32]; /* ESSID */
	uint8_t keyver; /* set to 1 if WPA is used, other values (preferably 2)
						   means WPA2  */
	uint8_t keymic[16]; /* the actual hash value (MD5 for WPA, SHA1 for WPA2)
						   truncated to 128 bit (16 bytes) */
	uint8_t mac_ap[6]; /* BSSID */
	uint8_t
		nonce_ap[32]; /* nonce (random salt) generated by the access point */
	uint8_t mac_sta[6]; /* mac address of the client connecting to the access
						   point */
	uint8_t nonce_sta[32]; /* nonce (random salt) generated by the client
							  connecting to the access point */
	uint16_t eapol_len; /* length of the EAPOL */
	uint8_t eapol[256]; /* EAPOL (max 256 bytes) */

} __attribute__((packed)) hccapx_t;

#endif
