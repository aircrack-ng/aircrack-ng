
// SHA-1 SSE2 implementation, (C) 2008 Alvaro Salmador (naplam33@msn.com), ported from Simon Marechal's SHA-1 MMX - License: GPLv2
// SHA-1 MMX implementation, (C) 2005 Simon Marechal (simon@banquise.net) - License: Public Domain

// This code computes two (with sse now four) SHA-1 digests at the same time. It
// doesn't take care of padding (0x80 and size << 3), so make
// sure the last input block is properly padded. Both 64-byte
// input blocks must be (four bytes) interleaved.

//  In addition, as a special exception, the copyright holders give
//  permission to link the code of portions of this program with the
//  OpenSSL library under certain conditions as described in each
//  individual source file, and distribute linked combinations
//  including the two.
//  You must obey the GNU General Public License in all respects
//  for all of the code used other than OpenSSL. *  If you modify
//  file(s) with this exception, you may extend this exception to your
//  version of the file(s), but you are not obligated to do so. *  If you
//  do not wish to do so, delete this exception statement from your
//  version. *  If you delete this exception statement from all source
//  files in the program, then also delete it here.

#if defined(__x86_64__) && defined(__APPLE__)
#define PRELOAD(x)
#define MANGLE(x) x(%rip)
#define INIT_PIC()
#define END_PIC()
#else
#ifdef __PIC__

#ifdef __x86_64__
#define PRELOAD(x)  movq x@GOTPCREL(%rip), %rbx;
#define MANGLE(x)   (%rbx)
#define INIT_PIC()  pushq %rbx
#define END_PIC()   popq  %rbx
#else
#undef __i686 /* gcc builtin define gets in our way */
#define PRELOAD(x)  
#define MANGLE(x)   x ## @GOTOFF(%ebx)
#define INIT_PIC() \
	call __i686.get_pc_thunk.bx ; \
	addl $_GLOBAL_OFFSET_TABLE_, %ebx
#define END_PIC()
#endif

#else

#define PRELOAD(x)  
#define MANGLE(x) x
#define INIT_PIC()
#define END_PIC()

#endif
#endif

#if defined(__i386__) || defined(__x86_64__)

.globl  shasse2_init;
.globl  shasse2_ends;
.globl  shasse2_data;
.globl  shasse2_cpuid;

.globl _shasse2_init;
.globl _shasse2_ends;
.globl _shasse2_data;
.globl _shasse2_cpuid;

.data
#ifdef __APPLE__
.align(12)
#else
.align(16)
#endif
const_init_a:
.long 0x67452301
.long 0x67452301
.long 0x67452301
.long 0x67452301
const_init_b:
.long 0xEFCDAB89
.long 0xEFCDAB89
.long 0xEFCDAB89
.long 0xEFCDAB89
const_init_c:
.long 0x98BADCFE
.long 0x98BADCFE
.long 0x98BADCFE
.long 0x98BADCFE
const_init_d:
.long 0x10325476
.long 0x10325476
.long 0x10325476
.long 0x10325476
const_init_e:
.long 0xC3D2E1F0
.long 0xC3D2E1F0
.long 0xC3D2E1F0
.long 0xC3D2E1F0
const_stage0:
.long 0x5A827999
.long 0x5A827999
.long 0x5A827999
.long 0x5A827999
const_stage1:
.long 0x6ED9EBA1
.long 0x6ED9EBA1
.long 0x6ED9EBA1
.long 0x6ED9EBA1
const_stage2:
.long 0x8F1BBCDC
.long 0x8F1BBCDC
.long 0x8F1BBCDC
.long 0x8F1BBCDC
const_stage3:
.long 0xCA62C1D6
.long 0xCA62C1D6
.long 0xCA62C1D6
.long 0xCA62C1D6
const_ff00:
.long 0xFF00FF00
.long 0xFF00FF00
.long 0xFF00FF00
.long 0xFF00FF00
const_00ff:
.long 0x00FF00FF
.long 0x00FF00FF
.long 0x00FF00FF
.long 0x00FF00FF

#define ctxa %xmm0
#define ctxb %xmm1
#define ctxc %xmm2
#define ctxd %xmm3
#define ctxe %xmm4
#define tmp1 %xmm5
#define tmp2 %xmm6
#define tmp3 %xmm7
#define tmp4 ctxa
#define tmp5 ctxb

#ifdef __x86_64__
 #define edx_rsi %rsi
 #define ecx_rdx %rdx
 #define eax_rdi %rdi
#else
 #define edx_rsi %edx
 #define ecx_rdx %ecx
 #define eax_rdi %eax
#endif

// movdqa movapd

#define F0(x,y,z)       \
        movdqa   x, tmp2; \
        movdqa   x, tmp1; \
        pand   y, tmp2; \
        pandn  z, tmp1; \
        por    tmp2, tmp1; 

#define F1(x,y,z)       \
        movdqa   z, tmp1; \
        pxor   y, tmp1; \
        pxor   x, tmp1

#define F2(x,y,z)       \
        movdqa   x, tmp1; \
        movdqa   x, tmp2; \
        pand   y, tmp1; \
        por    y, tmp2; \
        pand   z, tmp2; \
        por    tmp2, tmp1;
        
#if defined(__x86_64__) && defined(__CYGWIN__)
#define subRoundX(a, b, c, d, e, f, k, data)    \
        f(b,c,d);                               \
        movdqa   a, tmp2;                       \
        movdqa   a, tmp3;                       \
        paddd  tmp1, e;                         \
        pslld    $5, tmp2;                      \
        psrld   $27, tmp3;                      \
        por    tmp3, tmp2;                      \
        paddd  tmp2, e;                         \
        movdqa   b, tmp2;                       \
        pslld  $30, b;                          \
        paddd  MANGLE(k), e;			\
        psrld  $2, tmp2;                        \
        por    tmp2, b;                         \
        movdqa   (data*16)(edx_rsi), tmp1;      \
        movdqa   tmp1, tmp2;                    \
        pand   MANGLE(const_ff00), tmp1;        \
        pand   MANGLE(const_00ff), tmp2;        \
        psrld  $8, tmp1;                        \
        pslld  $8, tmp2;                        \
        por    tmp2, tmp1;                      \
        movdqa   tmp1, tmp2;                    \
        psrld  $16, tmp1;                       \
        pslld  $16, tmp2;                       \
        por    tmp2, tmp1;                      \
        movdqa   tmp1, (data*16)(ecx_rdx);      \
        paddd  tmp1, e;
#else
#define subRoundX(a, b, c, d, e, f, k, data)    \
        f(b,c,d);                               \
        movdqa   a, tmp2;                       \
        movdqa   a, tmp3;                       \
        paddd  tmp1, e;                         \
        pslld    $5, tmp2;                      \
        psrld   $27, tmp3;                      \
        por    tmp3, tmp2;                      \
        paddd  tmp2, e;                         \
        movdqa   b, tmp2;                       \
        pslld  $30, b;                          \
        PRELOAD(k)				\
        paddd  MANGLE(k), e;			\
        psrld  $2, tmp2;                        \
        por    tmp2, b;                         \
        movdqa   (data*16)(edx_rsi), tmp1;      \
        movdqa   tmp1, tmp2;                    \
        PRELOAD(const_ff00)			\
        pand   MANGLE(const_ff00), tmp1;        \
        PRELOAD(const_00ff)			\
        pand   MANGLE(const_00ff), tmp2;        \
        psrld  $8, tmp1;                        \
        pslld  $8, tmp2;                        \
        por    tmp2, tmp1;                      \
        movdqa   tmp1, tmp2;                    \
        psrld  $16, tmp1;                       \
        pslld  $16, tmp2;                       \
        por    tmp2, tmp1;                      \
        movdqa   tmp1, (data*16)(ecx_rdx);      \
        paddd  tmp1, e;
#endif

#if defined(__x86_64__) && defined(__CYGWIN__)
#define subRoundY(a, b, c, d, e, f, k, data)    \
	movdqa ((data- 3)*16)(ecx_rdx), tmp1;   \
        pxor   ((data- 8)*16)(ecx_rdx), tmp1;   \
        pxor   ((data-14)*16)(ecx_rdx), tmp1;   \
        pxor   ((data-16)*16)(ecx_rdx), tmp1;   \
        movdqa   tmp1, tmp2;                    \
        pslld    $1, tmp1;                      \
        psrld   $31, tmp2;                      \
        por    tmp2, tmp1;                      \
        movdqa  tmp1, (data*16)(ecx_rdx);       \
        paddd  tmp1, e;                         \
        f(b,c,d);                               \
        movdqa   a, tmp2;                       \
        movdqa   a, tmp3;                       \
        paddd  tmp1, e;                         \
        pslld    $5, tmp2;                      \
        psrld   $27, tmp3;                      \
        por    tmp3, tmp2;                      \
        paddd  tmp2, e;                         \
        movdqa   b, tmp2;                       \
        pslld  $30, b;                          \
        paddd  MANGLE(k), e;                    \
        psrld  $2, tmp2;                        \
        por    tmp2, b;
#else
#define subRoundY(a, b, c, d, e, f, k, data)    \
	movdqa ((data- 3)*16)(ecx_rdx), tmp1;   \
        pxor   ((data- 8)*16)(ecx_rdx), tmp1;   \
        pxor   ((data-14)*16)(ecx_rdx), tmp1;   \
        pxor   ((data-16)*16)(ecx_rdx), tmp1;   \
        movdqa   tmp1, tmp2;                    \
        pslld    $1, tmp1;                      \
        psrld   $31, tmp2;                      \
        por    tmp2, tmp1;                      \
        movdqa  tmp1, (data*16)(ecx_rdx);       \
        paddd  tmp1, e;                         \
        f(b,c,d);                               \
        movdqa   a, tmp2;                       \
        movdqa   a, tmp3;                       \
        paddd  tmp1, e;                         \
        pslld    $5, tmp2;                      \
        psrld   $27, tmp3;                      \
        por    tmp3, tmp2;                      \
        paddd  tmp2, e;                         \
        movdqa   b, tmp2;                       \
        pslld  $30, b;                          \
        PRELOAD(k)				\
        paddd  MANGLE(k), e;                    \
        psrld  $2, tmp2;                        \
        por    tmp2, b;
#endif 
.text

// arg 1 (eax) (64bit: rdi): context (4*20 bytes)

 shasse2_init:
_shasse2_init:

        INIT_PIC()
#if !defined(__x86_64__) && !defined(__CYGWIN__)
        PRELOAD(const_init_a)
#endif
        movdqa   MANGLE(const_init_a), ctxa
#if !defined(__x86_64__) && !defined(__CYGWIN__)
        PRELOAD(const_init_b)
#endif
        movdqa   MANGLE(const_init_b), ctxb
#if !defined(__x86_64__) && !defined(__CYGWIN__)
        PRELOAD(const_init_c)
#endif
        movdqa   MANGLE(const_init_c), ctxc
#if !defined(__x86_64__) && !defined(__CYGWIN__)
        PRELOAD(const_init_d)
#endif
        movdqa   MANGLE(const_init_d), ctxd
#if !defined(__x86_64__) && !defined(__CYGWIN__)
        PRELOAD(const_init_e)
#endif
        movdqa   MANGLE(const_init_e), ctxe

        movdqa   ctxa, 0(eax_rdi)
        movdqa   ctxb, 16(eax_rdi)
        movdqa   ctxc, 32(eax_rdi)
        movdqa   ctxd, 48(eax_rdi)
        movdqa   ctxe, 64(eax_rdi)
        END_PIC()

        ret

// arg 1 (eax) (64bit: rdi): context (4*20 bytes)
// arg 2 (edx) (64bit: rsi) : digests (4*20 bytes)

 shasse2_ends:
_shasse2_ends:

        INIT_PIC()
	movdqa    0(eax_rdi), ctxa
        movdqa   16(eax_rdi), ctxb
        movdqa   32(eax_rdi), ctxc
        movdqa   48(eax_rdi), ctxd
        movdqa   64(eax_rdi), ctxe

#if !defined(__x86_64__) && !defined(__CYGWIN__)
        PRELOAD(const_ff00)
#endif
        movdqa   MANGLE(const_ff00), tmp3
        movdqa   ctxa, tmp1
        movdqa   ctxb, tmp2
        pand   tmp3, ctxa
        pand   tmp3, ctxb
#if !defined(__x86_64__) && !defined(__CYGWIN__)
        PRELOAD(const_00ff)
#endif
        movdqa   MANGLE(const_00ff), tmp3
        pand   tmp3, tmp1
        pand   tmp3, tmp2
        psrld  $8, ctxa
        psrld  $8, ctxb
        pslld  $8, tmp1
        pslld  $8, tmp2
        por    tmp1, ctxa
        por    tmp2, ctxb
        movdqa   ctxa, tmp1
        movdqa   ctxb, tmp2
        psrld  $16, ctxa
        psrld  $16, ctxb
        pslld  $16, tmp1
        pslld  $16, tmp2
        por    tmp1, ctxa
        por    tmp2, ctxb 
        movdqa   ctxa,  0(edx_rsi)
        movdqa   ctxb,  16(edx_rsi)

#if !defined(__x86_64__) && !defined(__CYGWIN__)
        PRELOAD(const_ff00)
#endif
        movdqa   MANGLE(const_ff00), tmp5
        movdqa   ctxc, tmp1
        movdqa   ctxd, tmp2
        movdqa   ctxe, tmp3
        pand   tmp5, ctxc
        pand   tmp5, ctxd
        pand   tmp5, ctxe
#if !defined(__x86_64__) && !defined(__CYGWIN__)
        PRELOAD(const_00ff)
#endif
        movdqa   MANGLE(const_00ff), tmp5
        pand   tmp5, tmp1
        pand   tmp5, tmp2
        pand   tmp5, tmp3
        psrld  $8, ctxc
        psrld  $8, ctxd
        psrld  $8, ctxe
        pslld  $8, tmp1
        pslld  $8, tmp2
        pslld  $8, tmp3
        por    tmp1, ctxc
        por    tmp2, ctxd
        por    tmp3, ctxe
        movdqa   ctxc, tmp1
        movdqa   ctxd, tmp2
        movdqa   ctxe, tmp3
        psrld  $16, ctxc
        psrld  $16, ctxd
        psrld  $16, ctxe
        pslld  $16, tmp1
        pslld  $16, tmp2
        pslld  $16, tmp3
        por    tmp1, ctxc
        por    tmp2, ctxd
        por    tmp3, ctxe

        movdqa   ctxc, 32(edx_rsi)
        movdqa   ctxd, 48(edx_rsi)
        movdqa   ctxe, 64(edx_rsi)
        END_PIC()

        ret

// arg 1 (eax) (64bit: rdi): context     (4*20 bytes)
// arg 2 (edx) (64bit: rsi): input data (4*64 bytes)
// arg 3 (ecx) (64bit: rdx): workspace  (1280 bytes)

 shasse2_data:
_shasse2_data:

        INIT_PIC()
        movdqa    0(eax_rdi), ctxa
        movdqa   16(eax_rdi), ctxb
        movdqa   32(eax_rdi), ctxc
        movdqa   48(eax_rdi), ctxd
        movdqa   64(eax_rdi), ctxe

round0:

        prefetchnta (edx_rsi)

        subRoundX( ctxa, ctxb, ctxc, ctxd, ctxe, F0, const_stage0,  0 );
        subRoundX( ctxe, ctxa, ctxb, ctxc, ctxd, F0, const_stage0,  1 );
        subRoundX( ctxd, ctxe, ctxa, ctxb, ctxc, F0, const_stage0,  2 );
        subRoundX( ctxc, ctxd, ctxe, ctxa, ctxb, F0, const_stage0,  3 );
        subRoundX( ctxb, ctxc, ctxd, ctxe, ctxa, F0, const_stage0,  4 );
        subRoundX( ctxa, ctxb, ctxc, ctxd, ctxe, F0, const_stage0,  5 );
        subRoundX( ctxe, ctxa, ctxb, ctxc, ctxd, F0, const_stage0,  6 );
        subRoundX( ctxd, ctxe, ctxa, ctxb, ctxc, F0, const_stage0,  7 );
        subRoundX( ctxc, ctxd, ctxe, ctxa, ctxb, F0, const_stage0,  8 );
        subRoundX( ctxb, ctxc, ctxd, ctxe, ctxa, F0, const_stage0,  9 );
        subRoundX( ctxa, ctxb, ctxc, ctxd, ctxe, F0, const_stage0, 10 );
        subRoundX( ctxe, ctxa, ctxb, ctxc, ctxd, F0, const_stage0, 11 );
        subRoundX( ctxd, ctxe, ctxa, ctxb, ctxc, F0, const_stage0, 12 );
        subRoundX( ctxc, ctxd, ctxe, ctxa, ctxb, F0, const_stage0, 13 );
        subRoundX( ctxb, ctxc, ctxd, ctxe, ctxa, F0, const_stage0, 14 );
        subRoundX( ctxa, ctxb, ctxc, ctxd, ctxe, F0, const_stage0, 15 );
        subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F0, const_stage0, 16 );
        subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F0, const_stage0, 17 );
        subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F0, const_stage0, 18 );
        subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F0, const_stage0, 19 );

round1:

        subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage1, 20 );
        subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage1, 21 );
        subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage1, 22 );
        subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage1, 23 );
        subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage1, 24 );
        subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage1, 25 );
        subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage1, 26 );
        subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage1, 27 );
        subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage1, 28 );
        subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage1, 29 );
        subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage1, 30 );
        subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage1, 31 );
        subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage1, 32 );
        subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage1, 33 );
        subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage1, 34 );
        subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage1, 35 );
        subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage1, 36 );
        subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage1, 37 );
        subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage1, 38 );
        subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage1, 39 );

round2:

        subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F2, const_stage2, 40 );
        subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F2, const_stage2, 41 );
        subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F2, const_stage2, 42 );
        subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F2, const_stage2, 43 );
        subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F2, const_stage2, 44 );
        subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F2, const_stage2, 45 );
        subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F2, const_stage2, 46 );
        subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F2, const_stage2, 47 );
        subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F2, const_stage2, 48 );
        subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F2, const_stage2, 49 );
        subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F2, const_stage2, 50 );
        subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F2, const_stage2, 51 );
        subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F2, const_stage2, 52 );
        subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F2, const_stage2, 53 );
        subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F2, const_stage2, 54 );
        subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F2, const_stage2, 55 );
        subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F2, const_stage2, 56 );
        subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F2, const_stage2, 57 );
        subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F2, const_stage2, 58 );
        subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F2, const_stage2, 59 );

round3:

        subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage3, 60 );
        subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage3, 61 );
        subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage3, 62 );
        subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage3, 63 );
        subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage3, 64 );
        subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage3, 65 );
        subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage3, 66 );
        subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage3, 67 );
        subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage3, 68 );
        subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage3, 69 );
        subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage3, 70 );
        subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage3, 71 );
        subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage3, 72 );
        subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage3, 73 );
        subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage3, 74 );
        subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage3, 75 );
        subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage3, 76 );
        subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage3, 77 );
        subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage3, 78 );
        subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage3, 79 );

        paddd    0(eax_rdi), ctxa
        paddd   16(eax_rdi), ctxb
        paddd   32(eax_rdi), ctxc
        paddd   48(eax_rdi), ctxd
        paddd   64(eax_rdi), ctxe

        movdqa    ctxa,  0(eax_rdi)
        movdqa    ctxb, 16(eax_rdi)
        movdqa    ctxc, 32(eax_rdi)
        movdqa    ctxd, 48(eax_rdi)
        movdqa    ctxe, 64(eax_rdi)
        END_PIC()

        ret

// returns 0 if neither MMX nor SSE2 are supported; 1 if MMX is supported; 2 if SSE2 is also supported
 shasse2_cpuid:
_shasse2_cpuid:
#ifndef __x86_64__
		pushfl
		pushfl
		popl	%eax
		movl	%eax, %ecx
		xorl	$0x200000, %eax
		push	%eax
		popfl
		pushfl
		popl	%eax
		popfl
		xorl	%ecx, %eax
		jnz		do_cpuid
		ret
do_cpuid:
#endif   	

#ifdef __x86_64__
		push    %rbx
		push    %rcx
		push    %rdx
#else
		push	%ebx
		push	%ecx
		push	%edx
#endif		
   		movl	$1, %eax
   		cpuid
   		
		testl	$0x00800000, %edx  // bit 23 (MMX)
		jz		no_mmx
   		testl	$0x04000000, %edx  // bit 26 (SSE2)
   		jz		mmx_only
   		
		// sse2 supported:
		movl	$2, %eax
		jmp		cpuid_exit
		
mmx_only:
		movl	$1, %eax
		jmp		cpuid_exit

no_mmx:
		movl	$0, %eax

cpuid_exit:
#ifdef __x86_64__
		pop		%rdx
		pop		%rcx
		pop		%rbx
#else
		pop		%edx
		pop		%ecx
		pop		%ebx
#endif
		ret
#ifdef __i386__
#ifdef __PIC__
#ifndef __APPLE__
	.section .gnu.linkonce.t.__i686.get_pc_thunk.bx,"ax",@progbits
#endif
.globl __i686.get_pc_thunk.bx

#ifdef __APPLE__
    .private_extern  __i686.get_pc_thunk.bx
#else
	.hidden  __i686.get_pc_thunk.bx
	.type    __i686.get_pc_thunk.bx,@function
#endif
__i686.get_pc_thunk.bx:
	movl (%esp), %ebx
	ret
#endif
#endif
#endif


#ifdef __ELF__
.section .note.GNU-stack,"",%progbits
#endif
