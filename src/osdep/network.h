/*-
 * Copyright (c) 2007, 2008, Andrea Bittau <a.bittau@cs.ucl.ac.uk>
 *
 * Networking structures.
 *
 */

#ifndef __AIRCRACK_NG_OSDEP_NETWORK_H__
#define __AIRCRACK_NG_OSDEP_NETWORK_H__

#include <inttypes.h>
#include <sys/types.h>

#include "packed.h"

enum {
	NET_RC = 1,
	NET_GET_CHAN,
	NET_SET_CHAN,
	NET_WRITE,
	NET_PACKET,		/* 5 */
	NET_GET_MAC,
	NET_MAC,
	NET_GET_MONITOR,
	NET_GET_RATE,
	NET_SET_RATE,
};

struct net_hdr {
	uint8_t		nh_type;
	uint32_t	nh_len;
	uint8_t		nh_data[0];
} __packed;

extern struct wif *net_open(char *iface);
extern int net_send(int s, int command, void *arg, int len);
extern int net_read_exact(int s, void *arg, int len);
extern int net_get(int s, void *arg, int *len);



#if defined(__CYGWIN32__)

	#include <asm/byteorder.h>
	#include <unistd.h>

	#define ___my_be16cpu(x) \
	((u_int16_t)( \
			(((u_int16_t)(x) & (u_int16_t)0x00ffU) << 8) | \
			(((u_int16_t)(x) & (u_int16_t)0xff00U) >> 8) ))

	#define ___my_be32cpu(x) \
	((u_int32_t)( \
			(((u_int32_t)(x) & (u_int32_t)0x000000ffUL) << 24) | \
			(((u_int32_t)(x) & (u_int32_t)0x0000ff00UL) <<  8) | \
			(((u_int32_t)(x) & (u_int32_t)0x00ff0000UL) >>  8) | \
			(((u_int32_t)(x) & (u_int32_t)0xff000000UL) >> 24) ))

	#define ___my_be64cpu(x) \
	((u_int64_t)( \
			(u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x00000000000000ffULL) << 56) | \
			(u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x000000000000ff00ULL) << 40) | \
			(u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x0000000000ff0000ULL) << 24) | \
			(u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x00000000ff000000ULL) <<  8) | \
			(u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x000000ff00000000ULL) >>  8) | \
			(u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x0000ff0000000000ULL) >> 24) | \
			(u_int64_t)(((u_int64_t)(x) & (u_int64_t)0x00ff000000000000ULL) >> 40) | \
			(u_int64_t)(((u_int64_t)(x) & (u_int64_t)0xff00000000000000ULL) >> 56) ))



	#define __be64_to_cpu(x) ___my_be64cpu(x)
	#define __be32_to_cpu(x) ___my_be32cpu(x)
	#define __be16_to_cpu(x) ___my_be16cpu(x)
	#define __cpu_to_be64(x) ___my_be64cpu(x)
	#define __cpu_to_be32(x) ___my_be32cpu(x)
	#define __cpu_to_be16(x) ___my_be16cpu(x)
	#define __le64_to_cpu(x) (x)
	#define __le32_to_cpu(x) (x)
	#define __le16_to_cpu(x) (x)
	#define __cpu_to_le64(x) (x)
	#define __cpu_to_le32(x) (x)
	#define __cpu_to_le16(x) (x)



#endif /* __CYGWIN32__ */

#endif /* __AIRCRACK_NG_OSEDEP_NETWORK_H__ */
