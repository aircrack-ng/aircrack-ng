#include <stddef.h>
#include <errno.h>
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__NetBSD__)
	#include <sys/endian.h>
#elif defined(__APPLE__)
	#include <machine/endian.h>
	#include <libkern/OSByteOrder.h>

	#define htobe16(x) OSSwapHostToBigInt16(x)
	#define htole16(x) OSSwapHostToLittleInt16(x)
	#define be16toh(x) OSSwapBigToHostInt16(x)
	#define le16toh(x) OSSwapLittleToHostInt16(x)

	#define htobe32(x) OSSwapHostToBigInt32(x)
	#define htole32(x) OSSwapHostToLittleInt32(x)
	#define be32toh(x) OSSwapBigToHostInt32(x)
	#define le32toh(x) OSSwapLittleToHostInt32(x)

	#define htobe64(x) OSSwapHostToBigInt64(x)
	#define htole64(x) OSSwapHostToLittleInt64(x)
	#define be64toh(x) OSSwapBigToHostInt64(x)
	#define le64toh(x) OSSwapLittleToHostInt64(x)

	#define __BIG_ENDIAN    BIG_ENDIAN
	#define __LITTLE_ENDIAN LITTLE_ENDIAN
	#define __BYTE_ORDER    BYTE_ORDER
#elif !defined(__sun__)
	#include <endian.h>
#endif

#define le16_to_cpu		le16toh
#define le32_to_cpu		le32toh
#define get_unaligned(p)					\
({								\
	struct packed_dummy_struct {				\
		typeof(*(p)) __val;				\
	} __attribute__((packed)) *__ptr = (void *) (p);	\
								\
	__ptr->__val;						\
})
#define get_unaligned_le16(p)	le16_to_cpu(get_unaligned((uint16_t *)(p)))
#define get_unaligned_le32(p)	le32_to_cpu(get_unaligned((uint32_t *)(p)))
