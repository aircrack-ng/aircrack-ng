#include "channel_hopper.h"

#include <signal.h>

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
    )
{
    int ch, ch_idx = 0, card = 0, chi = 0, cai = 0, first = 1,
    again;
    int dropped = 0;

    /* Continue running as long as the parent is running. */
    while (0 == kill(parent, 0))
    {
        for (size_t j = 0; j < if_num; j++)
        {
            again = 1;

            ch_idx = chi % chan_count;

            card = cai % if_num;

            ++chi;
            ++cai;

            if (channel_switching_method == 2 && !first)
            {
                j = if_num - 1;
                card = if_num - 1;

                if (get_channel_count(possible_channels, true) > if_num)
                {
                    while (again)
                    {
                        again = 0;
                        for (size_t k = 0; k < if_num - 1; k++)
                        {
                            if (possible_channels[ch_idx] == current_channels[k])
                            {
                                again = 1;
                                ch_idx = chi % chan_count;
                                chi++;
                            }
                        }
                    }
                }
            }

            if (possible_channels[ch_idx] == invalid_channel)
            {
                j--;
                cai--;
                dropped++;
                if (dropped >= chan_count)
                {
                    ch = wi_get_channel(wi[card]);
                    current_channels[card] = ch;

                    struct channel_hopper_data_st const hopper_data =
                    {
                        .card = card,
                        .u.channel = ch
                    };

                    IGNORE_LTZ(write(data_write_fd, &hopper_data, sizeof hopper_data));

                    usleep(1000);
                }
                continue;
            }

            dropped = 0;

            ch = possible_channels[ch_idx];

#ifdef CONFIG_LIBNL
            if (wi_set_ht_channel(wi[card], ch, htval)== 0)
#else
            if (wi_set_channel(wi[card], ch)== 0)
#endif
            {
                current_channels[card] = ch;

                struct channel_hopper_data_st const hopper_data =
                {
                    .card = card,
                    .u.channel = ch
                };

                IGNORE_LTZ(write(data_write_fd, &hopper_data, sizeof hopper_data));

                if (do_active_probing)
                {
                    send_probe_request(wi[card]);
                }

                usleep(1000);
            }
            else
            {
                possible_channels[ch_idx] = invalid_channel;
                j--;
                cai--;
                continue;
            }
        }

        if (channel_switching_method == 0)
        {
            chi = chi - (if_num - 1);
        }

        if (first)
        {
            first = 0;
        }

        usleep((useconds_t)(hop_frequency_millisecs * 1000));
    }

    exit(0);
}

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
    pid_t const parent)
{
    int ch, ch_idx = 0, card = 0, chi = 0, cai = 0, first = 1,
    again;
    int dropped = 0;

    /* Continue running as long as the parent is running. */
    while (0 == kill(parent, 0))
    {
        for (size_t j = 0; j < if_num; j++)
        {
            again = 1;

            ch_idx = chi % chan_count;

            card = cai % if_num;

            ++chi;
            ++cai;

            if (channel_switching_method == channel_switching_method_hop_on_last
                && !first)
            {
                j = if_num - 1;
                card = if_num - 1;

                if (get_frequency_count(possible_frequencies, true) > if_num)
                {
                    while (again)
                    {
                        again = 0;
                        for (size_t k = 0; k <(if_num - 1); k++)
                        {
                            if (possible_frequencies[ch_idx]
                                == current_frequencies[k])
                            {
                                again = 1;
                                ch_idx = chi % chan_count;
                                chi++;
                            }
                        }
                    }
                }
            }

            if (possible_frequencies[ch_idx] == invalid_frequency)
            {
                j--;
                cai--;
                dropped++;
                if (dropped >= chan_count)
                {
                    ch = wi_get_freq(wi[card]);
                    current_frequencies[card] = ch;

                    struct channel_hopper_data_st const hopper_data =
                    {
                        .card = card,
                        .u.frequency = ch
                    };

                    IGNORE_LTZ(write(data_write_fd, &hopper_data, sizeof hopper_data));

                    usleep(1000);
                }
                continue;
            }

            dropped = 0;

            ch = possible_frequencies[ch_idx];

            if (wi_set_freq(wi[card], ch)== 0)
            {
                current_frequencies[card] = ch;

                struct channel_hopper_data_st const hopper_data =
                {
                    .card = card,
                    .u.frequency = ch
                };

                IGNORE_LTZ(write(data_write_fd, &hopper_data, sizeof hopper_data));

                usleep(1000);
            }
            else
            {
                possible_frequencies[ch_idx] = invalid_frequency;
                j--;
                cai--;
                continue;
            }
        }

        if (channel_switching_method == channel_switching_method_fifo)
        {
            chi = chi -(if_num - 1);
        }

        if (first)
        {
            first = 0;
        }

        usleep((useconds_t)(hop_frequency_millisecs * 1000));
    }

    exit(0);
}

