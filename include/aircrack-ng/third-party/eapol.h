#ifndef _NET_EAPOL_H_
#define _NET_EAPOL_H_

#include <stdint.h>

struct WPA_hdsk
{
	uint8_t stmac[6]; /* supplicant MAC           */
	uint8_t snonce[32]; /* supplicant nonce         */
	uint8_t anonce[32]; /* authenticator nonce      */
	uint8_t pmkid[16]; /* eapol frame PMKID RSN    */
	uint8_t keymic[16]; /* eapol frame MIC          */
	uint8_t eapol[256]; /* eapol frame contents     */
	uint32_t eapol_size; /* eapol frame size         */
	uint8_t keyver; /* key version (TKIP / AES) */
	uint8_t state; /* handshake completion     */
	uint8_t found;
	uint8_t eapol_source;
	uint64_t replay;
	uint64_t timestamp_start_us;
	uint64_t timestamp_last_us;
};

#endif // _NET_EAPOL_H_
