#ifndef __AIRODUMP_NG_DUMP_WRITE_PRIVATE__H__
#define __AIRODUMP_NG_DUMP_WRITE_PRIVATE__H__

#include "ap_list.h"
#include "aircrack-ng/osdep/sta_list.h"

struct dump_context_st
{
    void * priv;
    void (*dump)(void * const priv,
                 struct ap_list_head * const ap_list,
                 struct sta_list_head * const sta_list,
                 unsigned int const f_encrypt);
    void (*close)(void * const priv);
}; 

char * format_text_for_csv(uint8_t const * const input, size_t const len);

#endif /* __AIRODUMP_NG_DUMP_WRITE_PRIVATE__H__ */
