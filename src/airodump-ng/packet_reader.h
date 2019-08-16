#ifndef __PACKET_READER_H__
#define __PACKET_READER_H__

#include "aircrack-ng/osdep/osdep.h"
#include "aircrack-ng/support/pcap_local.h"

#include <stddef.h>

typedef struct packet_reader_context_st packet_reader_context_st;
typedef enum packet_reader_result_t
{
    packet_reader_result_done,
    packet_reader_result_skip,
    packet_reader_result_ok
} packet_reader_result_t;

packet_reader_context_st * packet_reader_open(char const * const filename);

void packet_reader_close(struct packet_reader_context_st * context);

packet_reader_result_t packet_reader_read(packet_reader_context_st * const context,
                                          void * const packet_buffer,
                                          size_t const buffer_size,
                                          size_t * const packet_length,
                                          struct rx_info * const ri,
                                          struct pcap_pkthdr * const pkh);

#endif /* __PACKET_READER_H__ */
