#ifndef __MAC_HEADER_H__
#define __MAC_HEADER_H__

#include "packed.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define __PACKED __packed

#define MAC_ADDRESS_LEN 6

typedef struct mac_address
{
    uint8_t addr[MAC_ADDRESS_LEN];
} __PACKED mac_address;

static mac_address const broadcast_mac = 
    { .addr = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };

static inline int MAC_ADDRESS_COMPARE(
    mac_address const * const a, 
    mac_address const * const b)
{
    return memcmp((void *)a, (void *)b, sizeof *a);
}

static inline bool MAC_ADDRESS_EQUAL(
    mac_address const * const a, 
    mac_address const * const b)
{
    return MAC_ADDRESS_COMPARE(a, b) == 0;
}

static inline bool MAC_ADDRESS_IS_EMPTY(
    mac_address const * const mac)
{
    mac_address const empty_mac = { .addr = { 0 } };

    return MAC_ADDRESS_EQUAL(mac, &empty_mac);
}

static inline bool MAC_ADDRESS_IS_BROADCAST(
    mac_address const * const mac)
{
    return MAC_ADDRESS_EQUAL(mac, &broadcast_mac);
}


static inline void MAC_ADDRESS_COPY(
    mac_address * const dest, 
    mac_address const * const src)
{
    *dest = *src;
}

static inline void MAC_ADDRESS_CLEAR(
    mac_address * const mac)
{
    mac_address const empty_mac = { .addr = { 0 } };

    MAC_ADDRESS_COPY(mac, &empty_mac);
}

static inline int fprintf_mac_address(
    FILE * const fp,
    mac_address const * const mac)
{
    return fprintf(
        fp,
        "%02X:%02X:%02X:%02X:%02X:%02X",
        mac->addr[0],
        mac->addr[1],
        mac->addr[2],
        mac->addr[3],
        mac->addr[4],
        mac->addr[5]);
}

#endif /* __MAC_HEADER_H__ */
