#ifndef __CHANNEL_HOPPER_H__
#define __CHANNEL_HOPPER_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "airodump-ng.h"
#include "aircrack-ng/osdep/osdep.h"

/* The channel/frequency hopper process sends these data 
 * structures over a pipe back to the main process. 
 * The main process then updates its record of the current 
 * channel/frequency. 
 */
struct channel_hopper_data_st
{
    int card;
    union
    {
        int frequency;
        int channel;
    } u;
}; 

void
channel_hopper(
    int const data_write_fd,
    struct wif * * const wi,
    int const if_num,
    int const chan_count,
    channel_switching_method_t const channel_switching_method,
    int * const possible_channels,
    int * const current_channels,
    bool const do_active_probing,
    int const hop_frequency_millisecs,
    pid_t const parent
#ifdef CONFIG_LIBNL
    , unsigned int const htval
#endif
    );

void
frequency_hopper(
    int const data_write_fd,
    struct wif * * const wi,
    int const if_num,
    int const chan_count,
    channel_switching_method_t const channel_switching_method,
    int * const possible_frequencies,
    int * const current_frequencies,
    int const hop_frequency_millisecs,
    pid_t const parent);

#endif /* __CHANNEL_HOPPER_H__ */

