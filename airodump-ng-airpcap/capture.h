#ifndef _CAPTURE_H
#define _CAPTURE_H

int load_peek( void );
int show_cards( void );
int set_channel( int channel );
int open_adapter( int card_index );
int start_monitor( void *callback );
void stop_monitor( void );
int GetNextPacket( char **payload, int *caplen, char *power);

#endif /* capture.h */
