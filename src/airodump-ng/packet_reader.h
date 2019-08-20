#ifndef __PACKET_READER_H__
#define __PACKET_READER_H__

#include "aircrack-ng/osdep/osdep.h"
#include "aircrack-ng/support/pcap_local.h"

#include <stddef.h>
#include <time.h>

typedef struct pcap_reader_context_st pcap_reader_context_st;
typedef enum pcap_reader_result_t
{
    pcap_reader_result_done,
    pcap_reader_result_skip,
    pcap_reader_result_ok
} pcap_reader_result_t;

pcap_reader_context_st * pcap_reader_open(char const * const filename);

void pcap_reader_close(struct pcap_reader_context_st * context);

pcap_reader_result_t pcap_read(
    pcap_reader_context_st * const context,
    void * const packet_buffer,
    size_t const buffer_size,
    size_t * const packet_length,
    struct rx_info * const ri,
    struct timeval * const packet_timestamp);

#endif /* __PACKET_READER_H__ */
