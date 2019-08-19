#include "packet_reader.h"
#include "aircrack-ng/support/common.h"
#include "radiotap/radiotap.h"
#include "radiotap/radiotap_iter.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

typedef packet_reader_result_t (* packet_reader_fn)(
    struct packet_reader_context_st * const packet_reader_context,
    uint8_t * const packet_buffer,
    size_t const buffer_size,
    size_t * const packet_length,
    struct rx_info * const ri);

struct packet_reader_context_st
{
    FILE * fp;
    struct pcap_file_header pfh_in;
    packet_reader_fn packet_reader;
};

static void packet_reader_free(struct packet_reader_context_st * context)
{
    if (context == NULL)
    {
        goto done;
    }

    if (context->fp != NULL)
    {
        fclose(context->fp);
    }

    free(context);

done:
    return;
}

void packet_reader_close(struct packet_reader_context_st * context)
{
    packet_reader_free(context);
}

static packet_reader_result_t packet_reader_80211(
    struct packet_reader_context_st * const packet_reader_context,
    uint8_t * const packet_buffer,
    size_t const buffer_size,
    size_t * const packet_length,
    struct rx_info * const ri)
{
    /* Nothing to do. */
    (void)packet_reader_context;
    (void)packet_buffer;
    (void)buffer_size;
    (void)packet_length;
    (void)ri;

    return packet_reader_result_ok;
}

static packet_reader_result_t packet_reader_prism(
    struct packet_reader_context_st * const packet_reader_context,
    uint8_t * const packet_buffer,
    size_t const buffer_size,
    size_t * const packet_length,
    struct rx_info * const ri)
{
    (void)packet_reader_context;
    (void)buffer_size;

    packet_reader_result_t result;
    uint32_t n;

    if (packet_buffer[7] == 0x40)
    {
        n = 64;
        ri->ri_power = -((int32_t)load32_le(packet_buffer + 0x33));
        ri->ri_noise = (int32_t)load32_le(packet_buffer + 0x33 + 12);
        ri->ri_rate = load32_le(packet_buffer + 0x33 + 24) * 500000;
    }
    else
    {
        n = load32_le(packet_buffer + 4);
        ri->ri_mactime = load64_le(packet_buffer + 0x5C - 48);
        ri->ri_channel = load32_le(packet_buffer + 0x5C - 36);
        ri->ri_power = -((int32_t)load32_le(packet_buffer + 0x5C));
        ri->ri_noise = (int32_t)load32_le(packet_buffer + 0x5C + 12);
        ri->ri_rate = load32_le(packet_buffer + 0x5C + 24) * 500000;
    }

    if (n < 8 || n >= *packet_length)
    {
        result = packet_reader_result_skip;
        goto done;
    }

    *packet_length -= n;
    memmove(packet_buffer, packet_buffer + n, *packet_length);

    result = packet_reader_result_ok;

done:
    return result;
}

static packet_reader_result_t packet_reader_radiotap(
    struct packet_reader_context_st * const packet_reader_context,
    uint8_t * const packet_buffer,
    size_t const buffer_size,
    size_t * const packet_length,
    struct rx_info * const ri)
{
    (void)packet_reader_context;
    (void)buffer_size;

    packet_reader_result_t result;
    uint32_t n;

    /* Remove the radiotap header. */

    n = load16_le(packet_buffer + 2);

    if (n == 0 || n >= *packet_length)
    {
        result = packet_reader_result_skip;
        goto done;
    }

    bool got_signal = false;
    bool got_noise = false;
    struct ieee80211_radiotap_iterator iterator;
    struct ieee80211_radiotap_header * rthdr;

    rthdr = (struct ieee80211_radiotap_header *)packet_buffer;

    if (ieee80211_radiotap_iterator_init(
            &iterator, rthdr, *packet_length, NULL)
        < 0)
    {
        result = packet_reader_result_skip;
        goto done;
    }

    /* Go through the radiotap arguments we have been given
     * by the driver
     */

    while (ieee80211_radiotap_iterator_next(&iterator) >= 0)
    {
        switch (iterator.this_arg_index)
        {
            case IEEE80211_RADIOTAP_TSFT:
                ri->ri_mactime = le64_to_cpu(
                    *((uint64_t *)iterator.this_arg));
                break;

            case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
            case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
                if (!got_signal)
                {
                    if (*iterator.this_arg < 127)
                    {
                        ri->ri_power = *iterator.this_arg;
                    }
                    else
                    {
                        ri->ri_power = *iterator.this_arg - 255;
                    }

                    got_signal = true;
                }
                break;

            case IEEE80211_RADIOTAP_DBM_ANTNOISE:
            case IEEE80211_RADIOTAP_DB_ANTNOISE:
                if (!got_noise)
                {
                    if (*iterator.this_arg < 127)
                    {
                        ri->ri_noise = *iterator.this_arg;
                    }
                    else
                    {
                        ri->ri_noise = *iterator.this_arg - 255;
                    }

                    got_noise = true;
                }
                break;

            case IEEE80211_RADIOTAP_ANTENNA:
                ri->ri_antenna = *iterator.this_arg;
                break;

            case IEEE80211_RADIOTAP_CHANNEL:
                ri->ri_channel = getChannelFromFrequency(
                    le16toh(*(uint16_t *)iterator.this_arg));
                break;

            case IEEE80211_RADIOTAP_RATE:
                ri->ri_rate = (*iterator.this_arg) * 500000;
                break;
        }
    }

    *packet_length -= n;
    memmove(packet_buffer, packet_buffer + n, *packet_length); 

    result = packet_reader_result_ok;

done:
    return result;
}

static packet_reader_result_t packet_reader_ppi(
    struct packet_reader_context_st * const packet_reader_context,
    uint8_t * const packet_buffer,
    size_t const buffer_size,
    size_t * const packet_length,
    struct rx_info * const ri)
{
    (void)packet_reader_context;
    (void)buffer_size;
    (void)ri;

    packet_reader_result_t result;
    uint32_t n;

    /* remove the PPI header */

    n = load16_le(packet_buffer + 2);

    if (n <= 0 || n >= *packet_length)
    {
        result = packet_reader_result_skip;
        goto done;
    }

    /* for a while Kismet logged broken PPI headers */
    if (n == 24 && load16_le(packet_buffer + 8) == 2)
    {
        n = 32;
    }

    if (n == 0 || n >= *packet_length)
    {
        result = packet_reader_result_skip;
        goto done;
    }

    *packet_length -= n;
    memmove(packet_buffer, packet_buffer + n, *packet_length); 

    result = packet_reader_result_ok;

done:
    return result;
}


packet_reader_result_t packet_reader_read(
    packet_reader_context_st * const context,
    void * const packet_buffer,
    size_t const buffer_size,
    size_t * const packet_length,
    struct rx_info * const ri,
    struct pcap_pkthdr * const pkh)
{
    packet_reader_result_t result;

    if (fread(pkh, 1, sizeof *pkh, context->fp) != sizeof *pkh)
    {
        result = packet_reader_result_done;
        goto done;
    }

    if (context->pfh_in.magic == TCPDUMP_CIGAM)
    {
        SWAP32(pkh->caplen);
        SWAP32(pkh->len);
    }

    if (pkh->caplen == 0 || pkh->caplen > buffer_size)
    {
        result = packet_reader_result_done;
        goto done;
    }

    *packet_length = pkh->caplen;

    if (fread(packet_buffer, 1, pkh->caplen, context->fp) != pkh->caplen)
    {
        result = packet_reader_result_done;
        goto done;
    }

    memset(ri, 0, sizeof *ri);

    result = 
        context->packet_reader(context, 
                               packet_buffer, 
                               buffer_size, 
                               packet_length, 
                               ri);

done:
    return result;
}

packet_reader_context_st * packet_reader_open(char const * const filename)
{
    struct packet_reader_context_st * context = calloc(1, sizeof *context);
    bool had_error = false;

    if (context == NULL)
    {
        perror("calloc failed");
        had_error = true;
        goto done;
    }

    context->fp = fopen(filename, "rb");
    if (context->fp == NULL)
    {
        perror("open failed");
        had_error = true;
        goto done;
    }

    if (fread(&context->pfh_in,
              1,
              sizeof context->pfh_in,
              context->fp)
        != sizeof context->pfh_in)
    {
        perror("fread(pcap file header) failed");
        had_error = true;
        goto done;
    }

    if (context->pfh_in.magic != TCPDUMP_MAGIC
        && context->pfh_in.magic != TCPDUMP_CIGAM)
    {
        fprintf(stderr,
                "\"%s\" isn't a pcap file (expected "
                "TCPDUMP_MAGIC).\n",
                filename);
        had_error = true;
        goto done;
    }

    if (context->pfh_in.magic == TCPDUMP_CIGAM)
    {
        SWAP32(context->pfh_in.linktype);
    }

    switch (context->pfh_in.linktype)
    {
        case LINKTYPE_IEEE802_11:
            context->packet_reader = packet_reader_80211;
            break;
        case LINKTYPE_PRISM_HEADER:
            context->packet_reader = packet_reader_prism;
            break;
        case LINKTYPE_RADIOTAP_HDR:
            context->packet_reader = packet_reader_radiotap;
            break;
        case LINKTYPE_PPI_HDR:
            context->packet_reader = packet_reader_ppi;
            break;
        default:
            fprintf(stderr,
                    "Wrong linktype from pcap file header "
                    "(expected LINKTYPE_IEEE802_11) -\n"
                    "this doesn't look like a regular 802.11 "
                    "capture.\n");
            had_error = true;
            goto done;
    }

    had_error = false;

done:
    if (had_error)
    {
        packet_reader_free(context);
        context = NULL;
    }

    return context;
}

