/*
 *  Copyright (c) 2007, 2008, Erik Tews, Andrei Pychkine and Ralf-Philipp Weinmann.
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "pcap.h"
#include "aircrack-ptw2-lib.h"
#include "aircrack-ng.h"

#define n PTW2_n
#define CONTROLSESSIONS PTW2_CONTROLSESSIONS
#define KSBYTES PTW2_KSBYTES
#define IVBYTES PTW2_IVBYTES
#define TESTBYTES 6


// Internal state of rc4
typedef struct {
	uint8_t i;
	uint8_t j;
	uint8_t s[n];
} rc4state;


// Helper structures for sorting
typedef struct {
	int keybyte;
	uint8_t value;
	int distance;
} sorthelper;

typedef struct {
	int keybyte;
	double difference;
} doublesorthelper;

// The rc4 initial state, the idendity permutation
static const uint8_t rc4initial[] =
{0,1,2,3,4,5,6,7,8,9,10,
11,12,13,14,15,16,17,18,19,20,
21,22,23,24,25,26,27,28,29,30,
31,32,33,34,35,36,37,38,39,40,
41,42,43,44,45,46,47,48,49,50,
51,52,53,54,55,56,57,58,59,60,
61,62,63,64,65,66,67,68,69,70,
71,72,73,74,75,76,77,78,79,80,
81,82,83,84,85,86,87,88,89,90,
91,92,93,94,95,96,97,98,99,100,
101,102,103,104,105,106,107,108,109,110,
111,112,113,114,115,116,117,118,119,120,
121,122,123,124,125,126,127,128,129,130,
131,132,133,134,135,136,137,138,139,140,
141,142,143,144,145,146,147,148,149,150,
151,152,153,154,155,156,157,158,159,160,
161,162,163,164,165,166,167,168,169,170,
171,172,173,174,175,176,177,178,179,180,
181,182,183,184,185,186,187,188,189,190,
191,192,193,194,195,196,197,198,199,200,
201,202,203,204,205,206,207,208,209,210,
211,212,213,214,215,216,217,218,219,220,
221,222,223,224,225,226,227,228,229,230,
231,232,233,234,235,236,237,238,239,240,
241,242,243,244,245,246,247,248,249,250,
251,252,253,254,255};

static const int coeffs[] =
{300, 260, 240, 240, 240, 100, 50, 50, 
30, 160, 30, 40, 30, 130, 40, 40, 
-120, 0, 16, 0, 100, 45};

/*
static const int coeffs[] =
{0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 16, 0, 100, 45};
*/

// Values for p_correct_i
static const double eval[] = {
0.00534392069257663,
0.00531787585068872,
0.00531345769225911,
0.00528812219217898,
0.00525997750378221,
0.00522647312237696,
0.00519132541143668,
0.0051477139367225,
0.00510438884847959,
0.00505484662057323,
0.00500502783556246,
0.00495094196451801,
0.0048983441590402};

int tried, max_tries;
int depth[KEYHSBYTES];
PTW2_tableentry keytable[KEYHSBYTES][n];

// For sorting
static int compare(const void * ina, const void * inb) {
        PTW2_tableentry * a = (PTW2_tableentry * )ina;
        PTW2_tableentry * b = (PTW2_tableentry * )inb;
        if (a->votes > b->votes) {
                return -1;
        } else if (a->votes == b->votes) {
                return 0;
        } else {
                return 1;
        }
}


// For sorting
/*
static int comparedoublesorthelper(const void * ina, const void * inb) {
        doublesorthelper * a = (doublesorthelper * )ina;
        doublesorthelper * b = (doublesorthelper * )inb;
        if (a->difference > b->difference) {
                return 1;
        } else if (a->difference == b->difference) {
                return 0;
        } else {
                return -1;
        }
}
*/

// RC4 key setup
static void rc4init ( uint8_t * key, int keylen, rc4state * state) {
	int i;
	unsigned char j;
	uint8_t tmp;
	memcpy(state->s, &rc4initial, n);
	j = 0;
	for (i = 0; i < n; i++) {
                /*  this should be:
                    j = (j + state->s[i] + key[i % keylen]) % n;
                    but as "j" is declared as unsigned char and n equals 256,
                    we can "optimize" it
                */
		j = (j + state->s[i] + key[i % keylen]);
		tmp = state->s[i];
		state->s[i] = state->s[j];
		state->s[j] = tmp;
	}
	state->i = 0;
	state->j = 0;
}

// RC4 key stream generation
static uint8_t rc4update(rc4state * state) {
	uint8_t tmp;
	uint8_t k;
	state->i++;
	state->j += state->s[state->i];
	tmp = state->s[state->i];
	state->s[state->i] = state->s[state->j];
	state->s[state->j] = tmp;
	k = state->s[state->i] + state->s[state->j];

	return state->s[k];
}

// For sorting
static int comparesorthelper(const void * ina, const void * inb) {
	sorthelper * a = (sorthelper * ) ina;
	sorthelper * b = (sorthelper * ) inb;
	if (a->distance > b->distance) {
		return 1;
	} else if (a->distance == b->distance) {
		return 0;
	} else {
		return -1;
	}
}

/*
 * Guess the values for sigma_i
 * ivlen - how long was the iv (is used differently in original klein attack)
 * iv - IV which was used for this packet
 * keystream - keystream recovered
 * result - buffer for the values of sigma_i
 * kb - how many keybytes should be guessed
 */
static void guesskeybytes(int ivlen, uint8_t * iv, uint8_t * keystream, uint8_t * result, int kb) {
        uint8_t state[n];
        uint8_t j = 0;
        uint8_t tmp;
        int i;
        int jj = ivlen;
        uint8_t ii;
        uint8_t s = 0;
        memcpy(state, rc4initial, n);
        for (i = 0; i < ivlen; i++) {
                j += state[i] + iv[i];
                tmp = state[i];
                state[i] = state[j];
                state[j] = tmp;
        }
        for (i = 0; i < kb; i++) {
                tmp = jj - keystream[jj-1];
                ii = 0;
                while(tmp != state[ii]) {
                        ii++;
                }
                s += state[jj];
                ii -= (j+s);
                result[i] = ii;
                jj++;
        }
        return;
}

/*
 * Is a guessed key correct?
 */
static int correct(PTW2_attackstate * state, uint8_t * key, int keylen) {
	int i;
        int j;
        int k;
        uint8_t keybuf[PTW2_KSBYTES];
        rc4state rc4state;

	// We need at least 3 sessions to be somehow certain
	if (state->sessions_collected < 3) {
		return 0;
	}

        tried++;

        k = rand()%(state->sessions_collected-10);
        for ( i=k; i < k+10; i++) {
                memcpy(&keybuf[IVBYTES], key, keylen);
                memcpy(keybuf, state->sessions[i].iv, IVBYTES);
                rc4init(keybuf, keylen+IVBYTES, &rc4state);
                for (j = 0; j < TESTBYTES; j++) {
                        if  ((rc4update(&rc4state) ^ state->sessions[i].keystream[j]) != 0) {
                                return 0;
                        }
                }
        }
        return 1;
}

/*
 * Calculate the squaresum of the errors for both distributions
 */
/*
static void getdrv(PTW2_tableentry orgtable[][n], int keylen, double * normal, double * ausreiser) {
        int i,j;
	int numvotes = 0;
        double e;
	double e2;
	double emax;
        double help = 0.0;
	double maxhelp = 0;
	double maxi = 0;
        for (i = 0; i < n; i++) {
                numvotes += orgtable[0][i].votes;
        }
        e = numvotes/n;
        for (i = 0; i < keylen; i++) {
		emax = eval[i] * numvotes;
		e2 = ((1.0 - eval[i])/255.0) * numvotes;
		normal[i] = 0;
		ausreiser[i] = 0;
		maxhelp = 0;
		maxi = 0;
		for (j = 0; j < n; j++) {
			if (orgtable[i][j].votes > maxhelp) {
				maxhelp = orgtable[i][j].votes;
				maxi = j;
			}
		}
                for (j = 0; j < n; j++) {
			if (j == maxi) {
				help = (1.0-orgtable[i][j].votes/emax);
			} else {
				help = (1.0-orgtable[i][j].votes/e2);
			}
			help = help*help;
			ausreiser[i] += help;
			help = (1.0-orgtable[i][j].votes/e);
			help = help*help;
			normal[i] += help;
                }
        }
}
*/


/*
 * Guess a single keybyte
 */
static int doRound(PTW2_tableentry sortedtable[][n], int keybyte, int fixat, uint8_t fixvalue, int * searchborders, uint8_t * key, int keylen, PTW2_attackstate * state, uint8_t sum, int * strongbytes, int * bf, int validchars[][n]) {
	int i;
	uint8_t tmp;

	if(!opt.is_quiet && keybyte < 4)
		show_wep_stats( keylen -1, 0, keytable, searchborders, depth, tried );
	if (keybyte > 0) {
		if (!validchars[keybyte-1][key[keybyte-1]]) {
			return 0;
		}
	}
	if (keybyte == keylen) {
		return correct(state, key, keylen);
	} else if (bf[keybyte] == 1) {
		for (i = 0; i < n; i++) {
			key[keybyte] = i;
			if (doRound(sortedtable, keybyte+1, fixat, fixvalue, searchborders, key, keylen, state, sum+i%n, strongbytes, bf, validchars)) {
				return 1;
			}
		}
		return 0;
        } else if (keybyte == fixat) {
                key[keybyte] = fixvalue-sum;
                return doRound(sortedtable, keybyte+1, fixat, fixvalue, searchborders, key, keylen, state, fixvalue, strongbytes, bf, validchars);
	} else if (strongbytes[keybyte] == 1) {
		// printf("assuming byte %d to be strong\n", keybyte);
		tmp = 3 + keybyte;
		for (i = keybyte-1; i >= 1; i--) {
			tmp += 3 + key[i] + i;
			key[keybyte] = n-tmp;
			if(doRound(sortedtable, keybyte+1, fixat, fixvalue, searchborders, key, keylen, state, (n-tmp+sum)%n, strongbytes, bf, validchars) == 1) {
				printf("hit with strongbyte for keybyte %d\n", keybyte);
				return 1;
			}
		}
		return 0;
	} else {
		for (i = 0; i < searchborders[keybyte]; i++) {
                    key[keybyte] = sortedtable[keybyte][i].b - sum;
                    if(!opt.is_quiet)
                    {
                        depth[keybyte] = i;
                        keytable[keybyte][i].b = key[keybyte];
                    }
                    if (doRound(sortedtable, keybyte+1, fixat, fixvalue, searchborders, key, keylen, state, sortedtable[keybyte][i].b, strongbytes, bf, validchars)) {
				return 1;
			}
		}
		return 0;
	}
}

/*
 * Do the actual computation of the key
 */
static int doComputation(PTW2_attackstate * state, uint8_t * key, int keylen, PTW2_tableentry table[][n], sorthelper * sh2, int * strongbytes, int keylimit, int * bf, int validchars[][n]) {
	int i,j;
	int choices[KEYHSBYTES];
	int prod;
	int fixat;
	int fixvalue;

        if(!opt.is_quiet)
            memcpy(keytable, table, sizeof(PTW2_tableentry) * n * keylen);

	for (i = 0; i < keylen; i++) {
		if (strongbytes[i] == 1) {
			choices[i] = i;
		} else {
			choices[i] = 1;
		}
	}
	i = 0;
	prod = 0;
	fixat = -1;
	fixvalue = 0;
        max_tries = keylimit;

	while(prod < keylimit) {
		if (doRound(table, 0, fixat, fixvalue, choices, key, keylen, state, 0, strongbytes, bf, validchars) == 1) {
			// printf("hit with %d choices\n", prod);
			if(!opt.is_quiet)
				show_wep_stats( keylen -1, 1, keytable, choices, depth, tried );
			return 1;
		}
		while( (i < (keylen-1) * (n-1)) && ((strongbytes[sh2[i].keybyte] == 1) || (bf[sh2[i].keybyte] == 1) ) ) {
			i++;
		}
		if(i >= ((keylen-1) * (n-1)))
		{
			break;
		}
		choices[sh2[i].keybyte]++;
		fixat = sh2[i].keybyte;
		// printf("choices[%d] is now %d\n", sh2[i].keybyte, choices[sh2[i].keybyte]);
		fixvalue = sh2[i].value;
		prod = 1;
		for (j = 0; j < keylen; j++) {
			prod *= choices[j];
			if (bf[j] == 1) {
				prod *= n;
			}
		}
		// printf("prod is now %d\n", prod);

                /*
		do {
			i++;
		} while (strongbytes[sh2[i].keybyte] == 1);
		*/
		i++;

		if(!opt.is_quiet)
			show_wep_stats( keylen -1, 0, keytable, choices, depth, tried );

	}
	if(!opt.is_quiet)
            show_wep_stats( keylen -1, 1, keytable, choices, depth, tried );
    return 0;
}


static void doVote(PTW2_tableentry first[][n], PTW2_tableentry second[][n], int i, int attack, int value, uint8_t * iv, int weight, int keylength) {
	int q = PTW2_IVBYTES;
	int j;
	if (i < keylength) {
            first[i][value].votes +=  coeffs[attack]*weight;
        } else if(i < q+keylength) {
            for (j = 0; j <= i-keylength; j++) {
                value = (value + 256 - iv[j])&0xff;
            }
	    // printf("doing iv vote\n");
            first[keylength-1][value].votes += coeffs[attack]*weight;
        } else {
            for (j = 0; j < q; j++) {
                value = (value + 256 - iv[j])&0xff;
            }
            second[i - (q+keylength)][value].votes += coeffs[attack]*weight;
        }
	
}

static void dumpTable(PTW2_tableentry table[][n], int keylen) {
	FILE * f;
	int i,j;

	f = fopen("tables.txt", "w");
	if (f != NULL) {
		for (i = 0; i < keylen; i++) {
			fprintf(f, "table %d\n", i);
			for (j = 0; j < n; j++) {
				fprintf(f, "byte %d with %d votes\n", table[i][j].b, table[i][j].votes);
			}
			fprintf(f, "\n");
		}
	}
	fclose(f);
}

static void genVotes(PTW2_tableentry first[][n], PTW2_tableentry second[][n], uint8_t * iv, uint8_t * ks, int * weights, int keylength) {
	int i;
        int j;
        int temp;
        int dq;
        int Kq;
        int jq;
        int j2;
        int t2;
	int q = PTW2_IVBYTES;
        
        int S[n];
        int Si[n];
        int jj[n];
        
        int numVotes = 2*keylength+q;
	// int numVotes = keylength;
        
        for (i = 0; i < n; i++) {
            S[i] = i;
        }
        
        j = 0;
        for (i = 0; i < q; i++) {
            j = (j + S[i] + iv[i])&0xff;
            jj[i] = j;
            temp = S[i];
            S[i] = S[j];
            S[j] = temp;
        }
        
        for (i = 0; i < 256; i++) {
            Si[S[i]] = i;
        }
        
        dq = j;
        for (i = 0; i < numVotes; i++) {
            dq = (dq + S[q+i])&0xff;
            temp = Si[(i+q-ks[i+q-1]+256)&0xff];
            Kq = (temp-dq+256)&0xff;
            int was_bad = 0;
	    int i2;
            for (i2 = q; i2 < q+i; i2++) {
                if (S[i2] == temp) {
                    doVote(first, second, i,A_ptw_bad, Kq, iv, weights[i+q-1], keylength);
                    // votes[i][A_ptw_bad][Kq]++;
                    was_bad = 1;
                    break;
                }
                
            }
            if (!was_bad) {
                doVote(first, second, i, A_ptw_good, Kq, iv, weights[i+q-1], keylength);
                // votes[i][A_ptw_good][Kq]++;
            }
            doVote(first, second, i, A_ptw, Kq, iv, weights[i+q-1], keylength);
            // votes[i][A_ptw][Kq]++; 
        }
        
        if (S[2] == 0) {
            if ((S[1] == 2) && (ks[0] == 2)) {
                dq = j;
                for (i = 0; i < numVotes; i++) {
                    dq = (dq + S[q+i])&0xff;
                    Kq = (1-dq+256)&0xff;
                    doVote(first, second, i, A_neg, Kq, iv, weights[0], keylength);
                    // votes[i][A_neg][Kq]++;
                    Kq = (2-dq+256)&0xff;
                    doVote(first, second, i, A_neg, Kq, iv, weights[0], keylength);
                    // votes[i][A_neg][Kq]++;
                }
            }
            else if (ks[1] == 0) {
                dq = j;
                for (i = 0; i < numVotes; i++) {
                    dq = (dq + S[q+i])&0xff;
                    Kq = (2 - dq + 256)&0xff;
                    doVote(first, second, i, A_neg, Kq, iv, weights[1], keylength);
                    // votes[i][A_neg][Kq]++;
                }
            }
        } else {
            dq = j;
            for (i = 0; i < numVotes; i++) {
                dq = (dq + S[q+i])&0xff;
                if ((ks[1] == 0) && (S[q+i] == 0)) {
                    
                    Kq = (2-dq+256)&0xff;
                    doVote(first, second, i, A_u15, Kq, iv, weights[1], keylength);
                    // votes[i][A_u15][Kq]++;
                }
            }
        }
        
        if ((S[1] == 1) && (ks[0] == S[2])) {
            dq = j;
            for (i = 0; i < numVotes; i++) {
                dq = (dq + S[q+i]) &0xff;
                Kq = (1-dq+256)&0xff;
                doVote(first, second, i, A_neg, Kq, iv, weights[0], keylength);
                // votes[i][A_neg][Kq]++;
                Kq = (2-dq+256)&0xff;
                doVote(first, second, i, A_neg, Kq, iv, weights[0], keylength);
                // votes[i][A_neg][Kq]++;
            }
        }
        
        if ((S[1] == 0) && (S[0] == 1) && (ks[0] == 1)) {
            dq = j;
            for (i = 0; i < numVotes; i++) {
                dq = (dq + S[q+i]) &0xff;
                Kq = (0-dq+256)&0xff;
                doVote(first, second, i, A_neg, Kq, iv, weights[0], keylength);
                // votes[i][A_neg][Kq]++;
                Kq = (1-dq+256)&0xff;
                doVote(first, second, i, A_neg, Kq, iv, weights[0], keylength);
                // votes[i][A_neg][Kq]++;
            }
        }
        
        dq = j;
        for (i = 0; i < numVotes; i++) {
            dq = (dq + S[q+i]) &0xff;
            if (S[1] == i+q) {
                if (ks[0] == q+i) {
                    Kq = (Si[0] - dq + 256)&0xff;
                    doVote(first, second, i, A_s13, Kq, iv, weights[0], keylength);
                    // votes[i][A_s13][Kq]++;
                } else if (((1 - (q+i) - ks[0] + 512)&0xff) == 0) {
                    Kq = (Si[ks[0]] - dq + 256)&0xff;
                    doVote(first, second, i, A_u13_1, Kq, iv, weights[0], keylength);
                    // votes[i][A_u13_1][Kq]++;
                } else if (Si[ks[0]] < q+i) {
                    jq = Si[(Si[ks[0]] - (q+i)+512)&0xff];
                    
                    if (jq != 1) {
                        Kq = (jq - dq+256)&0xff;
                        doVote(first, second, i, A_u5_1, Kq, iv, weights[0], keylength);
                        // votes[i][A_u5_1][Kq]++;
                    }
                }
                
            }
            
            if ((Si[ks[0]] == 2) && (S[q+i] == 1)) {
                Kq = (1-dq + 256)&0xff;
                doVote(first, second, i, A_u5_2, Kq, iv, weights[0], keylength);
                // votes[i][A_u5_2][Kq]++;
            }
            
            if (S[q+i] == q+i) {
                    if ((S[1] == 0) && (ks[0] == q+i)) {
                        Kq = (1-dq+256)&0xff;
                        doVote(first, second, i, A_u13_2, Kq, iv, weights[0], keylength);
                        // votes[i][A_u13_2][Kq]++;
                    } else if ((((1-(q+i)-S[1]+512)&0xff)==0) && (ks[0] == S[1])) {
                        Kq = (1-dq+256)&0xff;
                        doVote(first, second, i, A_u13_3, Kq, iv, weights[0], keylength);
                        // votes[i][A_u13_3][Kq]++;
                    } else if (S[1] >= (((512-(q+i))&0xff)) && ((((q+i)+S[1]-Si[ks[0]]+256)&0xff)== 0)) {
                        Kq = (1-dq+256)&0xff;
                        doVote(first, second, i, A_u5_3, Kq, iv, weights[0], keylength);
                        // votes[i][A_u5_3][Kq]++;
                    }
            }
            
            if (
                    (S[1] < (q)) && 
                    (((S[1]+S[S[1]] - (q+i) + 256)&0xff) == 0) && 
                    (Si[ks[0]] != 1) && 
                    (Si[ks[0]] != S[S[1]])) {
                Kq = (Si[ks[0]]-dq+256)&0xff;
                doVote(first, second, i, A_s5_1, Kq, iv, weights[0], keylength);
                // votes[i][A_s5_1][Kq]++;
            }
             
//            if (
//                    (S[1] > (q+i)) && 
//                    (((S[2] + S[1] - (q+i) + 256) & 0xff) == 0) &&
//                    (Si[ks[0]] != 1) && 
//                    (Si[ks[0]] != S[S[1]])
//                    ) {
//                Kq = (Si[ks[0]] - dq + 256)&0xff;
//                votes[i][A_s5_1][Kq]++;
//            }
            
            if ((S[1] > (q+i)) && (((S[2] + S[1] - (q+i) + 256)&0xff) == 0) ) {
                if (ks[1] == S[1]) {
                        jq = Si[(S[1] - S[2] + 256)&0xff];
                        if ((jq != 1) && (jq != 2)) {
                            Kq = (jq - dq + 256)&0xff;
                            doVote(first, second, i, A_s5_2, Kq, iv, weights[1], keylength);
                            // votes[i][A_s5_2][Kq]++;
                        }
                } else if (ks[1] == ((2-S[2]+256)&0xff)) {
                    jq = Si[ks[1]];
                    
                    if ((jq != 1) && (jq != 2)) {
                        Kq = (jq - dq + 256)&0xff;
                        doVote(first, second, i, A_s5_3, Kq, iv, weights[1], keylength);
                        // votes[i][A_s5_3][Kq]++;
                    }
                }
                
            }
            
            if ((S[1] != 2) && (S[2] != 0)) {
                j2 = (S[1] + S[2])&0xff;
                
                if (j2 < (q+i)) {
                    t2 = (S[j2] + S[2])&0xff ;
                    
                    if ((t2 == (q+i)) && (Si[ks[1]] != 1) && (Si[ks[1]] != 2) && (Si[ks[1]] != j2)) {
                        Kq = (Si[ks[1]] - dq + 256)&0xff;
                        doVote(first, second, i, A_s3, Kq, iv, weights[1], keylength);
                        // votes[i][A_s3][Kq]++;
                    }
                    
                }
            }
            
            if (S[1] == 2) {
                if ((q+i) == 4) {
                    if (ks[1] == 0) {
                        Kq = (Si[0] - dq + 256)&0xff;
                        doVote(first, second, i, A_4_s13, Kq, iv, weights[1], keylength);
                        // votes[i][A_4_s13][Kq]++;
                    } else {
                        if ((jj[1] == 2) && (Si[ks[1]] == 0)) {
                            Kq = (Si[254] - dq+256)&0xff;
                            doVote(first, second, i, A_4_u5_1, Kq, iv, weights[1], keylength);
                            // votes[i][A_4_u5_1][Kq]++;
                        }
                        if ((jj[1] == 2) && (Si[ks[1]] == 2)) {
                            Kq = (Si[255] - dq + 256)&0xff;
                            doVote(first, second, i, A_4_u5_2, Kq, iv, weights[1], keylength);
                            // votes[i][A_4_u5_2][Kq]++;
                        }
                    }
                }
                // We have to skip this attack
            }
        
        }

}


/*
 * Guess which key bytes could be strong and start actual computation of the key
 */
int PTW2_computeKey(PTW2_attackstate * state, uint8_t * keybuf, int keylen, int testlimit, int * bf, int validchars[][n], int attacks) {
	int strongbytes[KEYHSBYTES];
	/*
	double normal[KEYHSBYTES];
	double ausreisser[KEYHSBYTES];
	doublesorthelper helper[KEYHSBYTES];
	
	int simple, onestrong, twostrong;
	*/
	int i,j,t;
	uint8_t fullkeybuf[PTW2_KSBYTES];
	uint8_t guessbuf[PTW2_KSBYTES];
	sorthelper(*sh)[n-1];
	PTW2_tableentry (*table)[n] = alloca(sizeof(PTW2_tableentry) * n * keylen);
	PTW2_tableentry (*tablefirst)[n] = alloca(sizeof(PTW2_tableentry) * n * keylen);
	PTW2_tableentry (*tablesecond)[n] = alloca(sizeof(PTW2_tableentry) * n * keylen);

        tried=0;
	sh = NULL;

	if (table == NULL) {
		printf("could not allocate memory\n");
		exit(-1);
	}

	if(!(attacks & NO_KLEIN))
	{
		// Try the original klein attack first
		for (i = 0; i < keylen; i++) {
			bzero(&table[i][0], sizeof(PTW2_tableentry) * n);
			for (j = 0; j < n; j++) {
				table[i][j].b = j;
			}
			for (j = 0; j < state->packets_collected; j++) {
				// fullkeybuf[0] = state->allsessions[j].iv[0];
				memcpy(fullkeybuf, state->allsessions[j].iv, 3 * sizeof(uint8_t));
				guesskeybytes(i+3, fullkeybuf, state->allsessions[j].keystream, guessbuf, 1);
				table[i][guessbuf[0]].votes += state->allsessions[j].weight[i+2];
			}
			qsort(&table[i][0], n, sizeof(PTW2_tableentry), &compare);
			j = 0;
			while(!validchars[i][table[i][j].b]) {
				j++;
			}
			// printf("guessing i = %d, b = %d\n", i, table[0][0].b);
			fullkeybuf[i+3] = table[i][j].b;
		}
		if (correct(state, &fullkeybuf[3], keylen)) {
			memcpy(keybuf, &fullkeybuf[3], keylen * sizeof(uint8_t));
			// printf("hit without correction\n");
			return 1;
		}
	}


	if(!(attacks & NO_PTW2))
	{
		/*
		memcpy(table, state->table, sizeof(PTW2_tableentry) * n * keylen);

		onestrong = (testlimit/10)*2;
		twostrong = (testlimit/10)*1;
		simple = testlimit - onestrong - twostrong;

		// now, sort the table
		for (i = 0; i < keylen; i++) {
			qsort(&table[i][0], n, sizeof(PTW2_tableentry), &compare);
			strongbytes[i] = 0;
		}

		sh = alloca(sizeof(sorthelper) * (n-1) * keylen);
		if (sh == NULL) {
			printf("could not allocate memory\n");
			exit(-1);
		}


		for (i = 0; i < (keylen-1); i++) {
			for (j = 1; j < n; j++) {
				sh[i][j-1].distance = table[i][0].votes - table[i][j].votes;
				sh[i][j-1].value = table[i][j].b;
				sh[i][j-1].keybyte = i;
			}
		}
		qsort(sh, (n-1)*(keylen-1), sizeof(sorthelper), &comparesorthelper);


		if (doComputation(state, keybuf, keylen, table, (sorthelper *) sh, strongbytes, simple, bf, validchars)) {
			return 1;
		}

		// Now one strong byte
		getdrv(state->table, keylen, normal, ausreisser);
		for (i = 0; i < keylen-1; i++) {
			helper[i].keybyte = i+1;
			helper[i].difference = normal[i+1] - ausreisser[i+1];
		}
		qsort(helper, keylen-1, sizeof(doublesorthelper), &comparedoublesorthelper);
		// do not use bf-bytes as strongbytes
		i = 0;
		while(bf[helper[i].keybyte] == 1) {
			i++;
		}
		strongbytes[helper[i].keybyte] = 1;
		if (doComputation(state, keybuf, keylen, table, (sorthelper *) sh, strongbytes, onestrong, bf, validchars)) {
			return 1;
		}

		// two strong bytes
		i++;
		while(bf[helper[i].keybyte] == 1) {
			i++;
		}
		strongbytes[helper[i].keybyte] = 1;
		if (doComputation(state, keybuf, keylen, table, (sorthelper *) sh, strongbytes, twostrong, bf, validchars)) {
			return 1;
		}
		*/


		// First, init the tables
		for (i = 0; i < keylen; i++) {
			bzero(&table[i][0], sizeof(PTW2_tableentry) * n);
			bzero(&tablefirst[i][0], sizeof(PTW2_tableentry) * n);
			bzero(&tablesecond[i][0], sizeof(PTW2_tableentry) * n);

			for (j = 0; j < n; j++) {
				table[i][j].b = j;
				tablefirst[i][j].b = j;
				tablesecond[i][j].b = j;
			}
		}

		// Now, generate the votes
		for (i = 0; i < state->packets_collected; i++) {
			// fullkeybuf[0] = state->allsessions[j].iv[0];
			genVotes(tablefirst, tablesecond, state->allsessions[i].iv, state->allsessions[i].keystream, state->allsessions[i].weight, keylen);
		}
		
		// Votes generated, now execute the attack

		// First, we need to decide on the last keybyte. Fill the table for the last keybyte
		for (i = 0; i < n; i++) {		
			table[0][i].votes = tablefirst[keylen-1][i].votes;
		}
		qsort(&table[0][0], n, sizeof(PTW2_tableentry), &compare);
		// keybyte is now t
		t = table[0][0].b;

		// Now, correct the votes
		for (i = 0; i < keylen-1; i++) {
			for (j = 0; j < n; j++) {
				table[i][j].b = j;
				table[i][j].votes = (tablefirst[i][j].votes * coeffs[A_first]) + (tablesecond[i][(j+t)&0xff].votes * coeffs[A_second]);
			}
			qsort(&table[i][0], n, sizeof(PTW2_tableentry), &compare);
			strongbytes[i] = 0;
		}
		for (j = 0; j < n; j++) {
			table[keylen-1][j].b = j;
			table[keylen-1][j].votes = (tablefirst[keylen-1][j].votes * coeffs[A_first]);
			qsort(&table[keylen-1][0], n, sizeof(PTW2_tableentry), &compare);
		}

		strongbytes[keylen-1] = 0;
		
		// We can now start the usual key ranking thing
		sh = alloca(sizeof(sorthelper) * (n-1) * (keylen-1));
		if (sh == NULL) {
			printf("could not allocate memory\n");
			exit(-1);
		}
		for (i = 0; i < keylen-1; i++) {
			for (j = 1; j < n; j++) {
				sh[i][j-1].distance = table[i][0].votes - table[i][j].votes;
				sh[i][j-1].value = table[i][j].b;
				sh[i][j-1].keybyte = i;
			}
		}
		qsort(sh, (n-1)*(keylen-1), sizeof(sorthelper), &comparesorthelper);
		
		dumpTable(table, keylen);
		if (doComputation(state, keybuf, keylen, table, (sorthelper *) sh, strongbytes, testlimit, bf, validchars)) {
			return 1;
		}
		



	}
	return 0;
}

/*
 * Add a new session to the attack
 * state - state of attack
 * iv - IV used in the session
 * keystream - recovered keystream from the session
 */
int PTW2_addsession(PTW2_attackstate * state, uint8_t * iv, uint8_t * keystream, uint8_t * weight, int total) {
	int i,j,k;
	int il;
	int ir;
	// uint8_t buf[PTW2_KEYHSBYTES];

	i = (iv[0] << 16) | (iv[1] << 8) | (iv[2]);
	il = i/8;
	ir = 1 << (i%8);
	if ((state->seen_iv[il] & ir) == 0) {
		state->seen_iv[il] |= ir;
		for (j = 0; j < total; j++) {
			state->packets_collected++;
			// guesskeybytes(IVBYTES, iv, &keystream[KSBYTES*j], buf, PTW_KEYHSBYTES);
	                // for (i = 0; i < KEYHSBYTES; i++) {
	                // 	state->table[i][buf[i]].votes += weight[j];
	                // }
			if (state->allsessions_size < state->packets_collected) {
				state->allsessions_size = state->allsessions_size << 1;
				state->allsessions = realloc(state->allsessions, state->allsessions_size * sizeof(PTW2_session));
				if (state->allsessions == NULL) {
					printf("could not allocate memory\n");
					exit(-1);
				}
			}
			memcpy(state->allsessions[state->packets_collected-1].iv, iv, IVBYTES);
			memcpy(state->allsessions[state->packets_collected-1].keystream, &keystream[KSBYTES*j], KSBYTES);
			// memcpy(state->allsessions[state->packets_collected-1].weight,  &weight[KSBYTS*j], KSBYTES);
			for (k = 0; k < KSBYTES; k++) {
				state->allsessions[state->packets_collected-1].weight[k] = weight[KSBYTES*j+k];
			}

		}
                if ((state->sessions_collected < CONTROLSESSIONS)) {
                        memcpy(state->sessions[state->sessions_collected].iv, iv, IVBYTES);
                        memcpy(state->sessions[state->sessions_collected].keystream, keystream, KSBYTES);
                        state->sessions_collected++;
                }

		return 1;
	} else {
		return 0;
	}
}

/*
 * Allocate a new attackstate
 */
PTW2_attackstate * PTW2_newattackstate() {
	int i,k;
	PTW2_attackstate * state = NULL;
	state = malloc(sizeof(PTW2_attackstate));
	if (state == NULL) {
		return NULL;
	}
	bzero(state, sizeof(PTW2_attackstate));
	for (i = 0; i < PTW2_KEYHSBYTES; i++) {
                for (k = 0; k < n; k++) {
                        state->tablefirst[i][k].b = k;
			state->tablesecond[i][k].b = k;
                }
        }
	state->allsessions = malloc(4096 * sizeof(PTW2_session));
	state->allsessions_size = 4096;
	if (state->allsessions == NULL) {
		printf("could not allocate memory\n");
		exit(-1);
	}

        return state;
}

/*
 * Free an allocated attackstate
 */
void PTW2_freeattackstate(PTW2_attackstate * state) {
	free(state->allsessions);
	free(state);
	return;
}
