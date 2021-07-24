#include <stddef.h>
#include <errno.h>
#include <string.h>

#if defined(linux) || defined(Linux) || defined(__linux__) || defined(__linux) \
        || defined(__gnu_linux__)
#include <endian.h>
#if defined(__UCLIBC__)
#include <asm/byteorder.h>
#ifndef le16toh
#define le16toh __le16_to_cpu
#endif
#ifndef le32toh
#define le32toh __le32_to_cpu
#endif
#endif
#endif

#if defined(__CYGWIN32__) || defined(CYGWIN)
#include <asm/byteorder.h>
#include <endian.h>
#endif

#if defined(__APPLE__)
#include <machine/endian.h>
#endif

#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__OpenBSD__) || defined(__MidnightBSD__) || defined(__NetBSD__)
#include <sys/endian.h>
#include <sys/types.h>
#endif

#if defined(__SVR4) && defined(__sun__)
#include <sys/byteorder.h>
#include <sys/types.h>
#endif

#ifndef le16_to_cpu
#define le16_to_cpu		le16toh
#endif

#ifndef le32_to_cpu
#define le32_to_cpu		le32toh
#endif

#if defined(_MSC_VER)
//  Microsoft
#define EXPORT __declspec(dllexport)
#define IMPORT __declspec(dllimport)
#elif defined(__GNUC__) || defined(__llvm__) || defined(__clang__) || defined(__INTEL_COMPILER)
#define EXPORT __attribute__((visibility("default")))
#define IMPORT
#else
//  do nothing and hope for the best?
#define EXPORT
#define IMPORT
#pragma warning Unknown dynamic link import/export semantics.
#endif

#if defined(RADIOTAP_FAST_UNALIGNED_ACCESS)
#define get_unaligned(p)					\
__extension__({								\
	struct packed_dummy_struct {				\
		typeof(*(p)) __val;				\
	} __attribute__((packed)) *__ptr = (void *) (p);	\
								\
	__ptr->__val;						\
})
#else
#define get_unaligned(p)					\
__extension__({								\
 typeof(*(p)) __tmp;						\
 memmove(&__tmp, (p), sizeof(*(p)));				\
 __tmp;								\
})
#endif

#define get_unaligned_le16(p)	le16_to_cpu(get_unaligned((uint16_t *)(p)))
#define get_unaligned_le32(p)	le32_to_cpu(get_unaligned((uint32_t *)(p)))

#define UNALIGNED_ADDRESS(x) ((void*)(x))
