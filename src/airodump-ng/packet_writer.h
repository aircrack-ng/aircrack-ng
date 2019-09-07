#ifndef __PACKET_WRITER_H__
#define __PACKET_WRITER_H__

#include <stdint.h>
#include <stddef.h>

typedef enum packet_writer_type_t
{
	packet_writer_type_pcap,
	packet_writer_type_COUNT /* Keep the one at the end. */
} packet_writer_type_t;

typedef struct packet_writer_context_st packet_writer_context_st;

void packet_writer_write(struct packet_writer_context_st * const context,
						 uint8_t const * const packet,
						 size_t const packet_length,
						 int32_t const ri_power);

void packet_writer_close(struct packet_writer_context_st * const context);

struct packet_writer_context_st *
packet_writer_open(packet_writer_type_t const packet_writer_type,
				   char const * const filename);

#endif /* __PACKET_WRITER_H__ */
