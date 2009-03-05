/*
 * This file is meant to replace the code for the include and
 * all arch-specific defines.
 *
 * Note: It will be used later.
 */

#ifdef __MACH__
	#include <libkern/OSByteOrder.h>
#elif defined(__FreeBSD__)
	#include <machine/endian.h>
	#if BYTE_ORDER == BIG_ENDIAN
		# define __be32_to_cpu(x)       (x)
		# define __be64_to_cpu(x)       (x)
	#elif BYTE_ORDER == LITTLE_ENDIAN
		# define __be32_to_cpu(x)       __bswap32(x)
		# define __be64_to_cpu(x)       __bswap64(x)
	#endif
#elif defined (__sun) && defined (__sparc) /* Solaris SPARC, not Solaris x86 */
	#include <sys/byteorder.h>
#else
	#include <asm/byteorder.h>
#endif /* __MACH__ */
