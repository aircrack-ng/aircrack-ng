#ifndef __PACKET_WRITER_PCAP_H__
#define __PACKET_WRITER_PCAP_H__

#include "packet_writer.h"

#include <stdbool.h>

bool pcap_packet_writer_open(
    packet_writer_context_st * const context,
    char const * const filename);

#endif /* __PACKET_WRITER_PCAP_H__ */
