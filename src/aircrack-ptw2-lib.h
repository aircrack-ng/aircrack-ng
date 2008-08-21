/*
 * Copyright (c) 2007, Erik Tews, Andrei Pychkine and Ralf-Philipp Weinmann.
 *
 */

#ifndef _AIRCRACK_PTW2_H_
#define _AIRCRACK_PTW2_H_

#include <stdint.h>

// Number of bytes we use for our table of seen IVs, this is (2^24)/8
#define PTW2_IVTABLELEN 2097152

// How many sessions do we use to check if a guessed key is correct
// 10 seems to be a reasonable choice
// Its now the number of sessions for selecting 10 at a random position
#define PTW2_CONTROLSESSIONS 10000

// The maximum possible length of the main key, 13 is the maximum for a 104 bit key
#define PTW2_KEYHSBYTES 29

// How long the IV is, 3 is the default value for WEP
#define PTW2_IVBYTES 3

// How many bytes of a keystream we collect, 16 are needed for a 104 bit key
#define PTW2_KSBYTES 64

// The MAGIC VALUE!!
#define PTW2_n 256

// distinguish klein and ptw
#define NO_KLEIN  0x01
#define NO_PTW2   0x02

// We use this to keep track of the outputs of A_i
typedef struct {
	// How often the value b appeard as an output of A_i
	int votes;

	uint8_t b;
} PTW2_tableentry;

// A recovered session
typedef struct {
	// The IV used in this session
        uint8_t iv[PTW2_IVBYTES];
	// The keystream used in this session
        uint8_t keystream[PTW2_KSBYTES];
	// Weight for this session
	int weight[PTW2_KSBYTES];
} PTW2_session;

// The state of an attack
// You should usually never modify these values manually
typedef struct {
	// How many unique packets or IVs have been collected
        int packets_collected;
	// Table to check for duplicate IVs
        uint8_t seen_iv[PTW2_IVTABLELEN];
	// How many sessions for checking a guessed key have been collected
        int sessions_collected;
	// The actual recovered sessions
        PTW2_session sessions[PTW2_CONTROLSESSIONS];
	// The table with votes for the keybytesums
        PTW2_tableentry tablefirst[PTW2_KEYHSBYTES][PTW2_n];
	// The table with the votes from the second round
	PTW2_tableentry tablesecond[PTW2_KEYHSBYTES][PTW2_n];
	// Sessions for the original klein attack
	PTW2_session * allsessions;
	int allsessions_size;
	// Length of the key, we are going to attack
	int keylength;
} PTW2_attackstate;

PTW2_attackstate * PTW2_newattackstate();
void PTW2_freeattackstate(PTW2_attackstate *);
int PTW2_addsession(PTW2_attackstate *, uint8_t *, uint8_t *, uint8_t *, int);
int PTW2_computeKey(PTW2_attackstate *, uint8_t *, int, int, int *, int [][PTW2_n], int attacks);

#endif
