
// SHA-1 MMX implementation, (C) 2005 Simon Marechal

// This code computes two SHA-1 digests at the same time. It
// doesn't take care of padding (0x80 and size << 3), so make
// sure the last input block is properly padded. Both 64-byte
// input blocks must be (four bytes) interleaved.

#ifdef __i386__

.globl  shammx_init;
.globl  shammx_ends;
.globl  shammx_data;

.globl _shammx_init;
.globl _shammx_ends;
.globl _shammx_data;

.data
.align(4)
const_init_a:
.long 0x67452301
.long 0x67452301
const_init_b:
.long 0xEFCDAB89
.long 0xEFCDAB89
const_init_c:
.long 0x98BADCFE
.long 0x98BADCFE
const_init_d:
.long 0x10325476
.long 0x10325476
const_init_e:
.long 0xC3D2E1F0
.long 0xC3D2E1F0
const_stage0:
.long 0x5A827999
.long 0x5A827999
const_stage1:
.long 0x6ED9EBA1
.long 0x6ED9EBA1
const_stage2:
.long 0x8F1BBCDC
.long 0x8F1BBCDC
const_stage3:
.long 0xCA62C1D6
.long 0xCA62C1D6
const_ff00:
.long 0xFF00FF00
.long 0xFF00FF00
const_00ff:
.long 0x00FF00FF
.long 0x00FF00FF

#define ctxa %mm0
#define ctxb %mm1
#define ctxc %mm2
#define ctxd %mm3
#define ctxe %mm4
#define tmp1 %mm5
#define tmp2 %mm6
#define tmp3 %mm7
#define tmp4 ctxa
#define tmp5 ctxb

#define F0(x,y,z)       \
        movq   x, tmp2; \
        movq   x, tmp1; \
        pand   y, tmp2; \
        pandn  z, tmp1; \
        por    tmp2, tmp1; 

#define F1(x,y,z)       \
        movq   z, tmp1; \
        pxor   y, tmp1; \
        pxor   x, tmp1

#define F2(x,y,z)       \
        movq   x, tmp1; \
        movq   x, tmp2; \
        pand   y, tmp1; \
        por    y, tmp2; \
        pand   z, tmp2; \
        por    tmp2, tmp1;
        
#define subRoundX(a, b, c, d, e, f, k, data)    \
        f(b,c,d);                               \
        movq   a, tmp2;                         \
        movq   a, tmp3;                         \
        paddd  tmp1, e;                         \
        pslld    $5, tmp2;                      \
        psrld   $27, tmp3;                      \
        por    tmp3, tmp2;                      \
        paddd  tmp2, e;                         \
        movq   b, tmp2;                         \
        pslld  $30, b;                          \
        paddd  k, e;                            \
        psrld  $2, tmp2;                        \
        por    tmp2, b;                         \
        movq   (data*8)(%edx), tmp1;            \
        movq   tmp1, tmp2;                      \
        pand   const_ff00, tmp1;                \
        pand   const_00ff, tmp2;                \
        psrld  $8, tmp1;                        \
        pslld  $8, tmp2;                        \
        por    tmp2, tmp1;                      \
        movq   tmp1, tmp2;                      \
        psrld  $16, tmp1;                       \
        pslld  $16, tmp2;                       \
        por    tmp2, tmp1;                      \
        movq   tmp1, (data*8)(%ecx);            \
        paddd  tmp1, e;

#define subRoundY(a, b, c, d, e, f, k, data)    \
        movq   ((data- 3)*8)(%ecx), tmp1;       \
        pxor   ((data- 8)*8)(%ecx), tmp1;       \
        pxor   ((data-14)*8)(%ecx), tmp1;       \
        pxor   ((data-16)*8)(%ecx), tmp1;       \
        movq   tmp1, tmp2;                      \
        pslld    $1, tmp1;                      \
        psrld   $31, tmp2;                      \
        por    tmp2, tmp1;                      \
        movq   tmp1, (data*8)(%ecx);            \
        paddd  tmp1, e;                         \
        f(b,c,d);                               \
        movq   a, tmp2;                         \
        movq   a, tmp3;                         \
        paddd  tmp1, e;                         \
        pslld    $5, tmp2;                      \
        psrld   $27, tmp3;                      \
        por    tmp3, tmp2;                      \
        paddd  tmp2, e;                         \
        movq   b, tmp2;                         \
        pslld  $30, b;                          \
        paddd  k, e;                            \
        psrld  $2, tmp2;                        \
        por    tmp2, b;

.text

// arg 1 (eax): context (40 bytes)

 shammx_init:
_shammx_init:

        movq   const_init_a, ctxa
        movq   const_init_b, ctxb
        movq   const_init_c, ctxc
        movq   const_init_d, ctxd
        movq   const_init_e, ctxe

        movq   ctxa,  0(%eax)
        movq   ctxb,  8(%eax)
        movq   ctxc, 16(%eax)
        movq   ctxd, 24(%eax)
        movq   ctxe, 32(%eax)

        ret

// arg 1 (eax): context (40 bytes)
// arg 2 (edx): digests (40 bytes)

 shammx_ends:
_shammx_ends:

        movq    0(%eax), ctxa
        movq    8(%eax), ctxb
        movq   16(%eax), ctxc
        movq   24(%eax), ctxd
        movq   32(%eax), ctxe

        movq   const_ff00, tmp3
        movq   ctxa, tmp1
        movq   ctxb, tmp2
        pand   tmp3, ctxa
        pand   tmp3, ctxb
        movq   const_00ff, tmp3
        pand   tmp3, tmp1
        pand   tmp3, tmp2
        psrld  $8, ctxa
        psrld  $8, ctxb
        pslld  $8, tmp1
        pslld  $8, tmp2
        por    tmp1, ctxa
        por    tmp2, ctxb
        movq   ctxa, tmp1
        movq   ctxb, tmp2
        psrld  $16, ctxa
        psrld  $16, ctxb
        pslld  $16, tmp1
        pslld  $16, tmp2
        por    tmp1, ctxa
        por    tmp2, ctxb 
        movq   ctxa,  0(%edx)
        movq   ctxb,  8(%edx)

        movq   const_ff00, tmp5
        movq   ctxc, tmp1
        movq   ctxd, tmp2
        movq   ctxe, tmp3
        pand   tmp5, ctxc
        pand   tmp5, ctxd
        pand   tmp5, ctxe
        movq   const_00ff, tmp5
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
        movq   ctxc, tmp1
        movq   ctxd, tmp2
        movq   ctxe, tmp3
        psrld  $16, ctxc
        psrld  $16, ctxd
        psrld  $16, ctxe
        pslld  $16, tmp1
        pslld  $16, tmp2
        pslld  $16, tmp3
        por    tmp1, ctxc
        por    tmp2, ctxd
        por    tmp3, ctxe

        movq   ctxc, 16(%edx)
        movq   ctxd, 24(%edx)
        movq   ctxe, 32(%edx)

        ret

// arg 1 (eax): context     (40 bytes)
// arg 2 (edx): input data (128 bytes)
// arg 3 (ecx): workspace  (640 bytes)

 shammx_data:
_shammx_data:

        movq    0(%eax), ctxa
        movq    8(%eax), ctxb
        movq   16(%eax), ctxc
        movq   24(%eax), ctxd
        movq   32(%eax), ctxe

round0:

        prefetchnta (%edx)

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

        paddd    0(%eax), ctxa
        paddd    8(%eax), ctxb
        paddd   16(%eax), ctxc
        paddd   24(%eax), ctxd
        paddd   32(%eax), ctxe

        movq    ctxa,  0(%eax)
        movq    ctxb,  8(%eax)
        movq    ctxc, 16(%eax)
        movq    ctxd, 24(%eax)
        movq    ctxe, 32(%eax)

        ret

#endif


#ifdef __ELF__
.section .note.GNU-stack,"",%progbits
#endif
