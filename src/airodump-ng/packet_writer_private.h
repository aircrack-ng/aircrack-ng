#ifndef __PACKET_WRITER_PRIVATE__H__
#define __PACKET_WRITER_PRIVATE__H__

#include <stdint.h>
#include <stddef.h>

struct packet_writer_context_st
{
    void * priv;

    void (*write)(void * const priv,
                  uint8_t const * const packet,
                  size_t const packet_length,
                  int32_t const ri_power);

    void (*close)(void * const priv);
}; 

#endif /* __PACKET_WRITER_PRIVATE__H__ */
