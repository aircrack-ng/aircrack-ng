/*
 * Copyright (c) 2007, Erik Tews, Andrei Pychkine and Ralf-Philipp Weinmann.
 *
 */

#ifndef _AIRCRACK_PTW_H_
#define _AIRCRACK_PTW_H_

#include <stdint.h>

// Number of bytes we use for our table of seen IVs, this is (2^24)/8
#define PTW_IVTABLELEN 2097152

// How many sessions do we use to check if a guessed key is correct
// 10 seems to be a reasonable choice
// Its now the number of sessions for selecting 10 at a random position
#define PTW_CONTROLSESSIONS 10000

// The maximum possible length of the main key, 13 is the maximum for a 104 bit key
#define PTW_KEYHSBYTES 29

// How long the IV is, 3 is the default value for WEP
#define PTW_IVBYTES 3

// How many bytes of a keystream we collect, 16 are needed for a 104 bit key
#define PTW_KSBYTES 32

// The MAGIC VALUE!!
#define PTW_n 256

// distinguish klein and ptw
#define NO_KLEIN 0x01
#define NO_PTW   0x02

// We use this to keep track of the outputs of A_i
typedef struct {
	// How often the value b appeard as an output of A_i
	int votes;

	uint8_t b;
} PTW_tableentry;

// A recovered session
typedef struct {
	// The IV used in this session
        uint8_t iv[PTW_IVBYTES];
	// The keystream used in this session
        uint8_t keystream[PTW_KSBYTES];
	// Weight for this session
	int weight;
} PTW_session;

// The state of an attack
// You should usually never modify these values manually
typedef struct {
	// How many unique packets or IVs have been collected
        int packets_collected;
	// Table to check for duplicate IVs
        uint8_t seen_iv[PTW_IVTABLELEN];
	// How many sessions for checking a guessed key have been collected
        int sessions_collected;
	// The actual recovered sessions
        PTW_session sessions[PTW_CONTROLSESSIONS];
	// The table with votes for the keybytesums
        PTW_tableentry table[PTW_KEYHSBYTES][PTW_n];
	// Sessions for the original klein attack
	PTW_session * allsessions;
	int allsessions_size;
} PTW_attackstate;

PTW_attackstate * PTW_newattackstate();
void PTW_freeattackstate(PTW_attackstate *);
int PTW_addsession(PTW_attackstate *, uint8_t *, uint8_t *, int *, int);
int PTW_computeKey(PTW_attackstate *, uint8_t *, int, int, int *, int [][PTW_n], int attacks);

#endif
