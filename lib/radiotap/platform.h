#include <stddef.h>
#include <errno.h>
#include <string.h>
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#if defined(RADIOTAP_FAST_UNALIGNED_ACCESS)
#define get_unaligned(p)					\
({								\
	struct packed_dummy_struct {				\
		typeof(*(p)) __val;				\
	} __attribute__((packed)) *__ptr = (void *) (p);	\
								\
	__ptr->__val;						\
})
#else
#define get_unaligned(p)					\
({								\
 typeof(*(p)) __tmp;						\
 memmove(&__tmp, (p), sizeof(*(p)));				\
 __tmp;								\
})
#endif

#define get_unaligned_le16(p)	le16_to_cpu(get_unaligned((uint16_t *)(p)))
#define get_unaligned_le32(p)	le32_to_cpu(get_unaligned((uint32_t *)(p)))

#define UNALIGNED_ADDRESS(x) ((void*)(x))
