#ifndef _GCRYPT_OPENSSL_WRAPPER_H
#define _GCRYPT_OPENSSL_WRAPPER_H
/*
 *
 * gcrypt-openssl-wrapper.h
 *
 * Copyright (C) 2012 Carlos Alberto Lopez Perez <clopez@igalia.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 */
#include <gcrypt.h>
// RC4_*
#define RC4_KEY                                         gcry_cipher_hd_t
#define RC4_set_key(h, l, k)                            do { \
                                                            gcry_cipher_open(h, GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM, 0); \
                                                            gcry_cipher_setkey(*h, k, l); \
                                                        } while (0)
                                                        // we need to release the handle to avoid memory leaks.
                                                        // And in the actual code there are not repeat calls to RC4() without calling
                                                        // RC4_set_key() first, so we can encapsulate the call to gcry_cipher_close() inside RC4()
                                                        // This should be changed if you call RC4() without calling RC4_set_key before
#define RC4(h, l, s, d)                                 do { \
                                                            gcry_cipher_encrypt(*h, d, l, s, l) ; \
                                                            gcry_cipher_close(*h); \
                                                        } while(0)
// SHA_* (We use the sha1-git implementation because is much faster)
#define SHA_CTX                                         blk_SHA_CTX
#define SHA1_Init(ctx)                                  blk_SHA1_Init(ctx)
#define SHA1_Update(ctx,buffer,len)                     blk_SHA1_Update(ctx,buffer,len)
#define SHA1_Final(digest,ctx)                          blk_SHA1_Final(digest,ctx)
// EVP_*
#define EVP_md5()                                       GCRY_MD_MD5
#define EVP_sha1()                                      GCRY_MD_SHA1
// AES_*
#define AES_KEY                                         gcry_cipher_hd_t
#define AES_encrypt(text, enc_out, ctx)                 gcry_cipher_encrypt(*ctx, enc_out, 16, text, 16)
#define AES_set_encrypt_key(key, len, ctx)              do  { \
                                                            gcry_cipher_open(ctx, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_ECB, 0); \
                                                            gcry_cipher_setkey(*ctx, key, len/8); \
                                                        } while (0)
// HMAC_*
#define HMAC_CTX                                        gcry_md_hd_t
#define HMAC_CTX_cleanup(ctx)                           gcry_md_close(*ctx)
#define HMAC_CTX_init(ctx)                              ; // noop
#define HMAC_Init_ex(ctx, key, len, md, engine)         HMAC_Init(ctx, key, len, md)
#define HMAC_Init(ctx, key, len, md)                    do  { \
                                                            if ((len==0)||(key==NULL)||(md==0)) { \
                                                                gcry_md_reset(*ctx); \
                                                            } else { \
                                                                gcry_md_open(ctx, md, GCRY_MD_FLAG_HMAC); \
                                                                gcry_md_setkey(*ctx, key, len); \
                                                            } \
                                                        }  while (0)
#define HMAC_Update(ctx, data, len)                     gcry_md_write(*ctx, data, len)
#define HMAC_Final(ctx, md, len)                        do  { \
                                                            memcpy(   md,  \
                                                                gcry_md_read(*ctx, 0), \
                                                                gcry_md_get_algo_dlen(gcry_md_get_algo(*ctx)) \
                                                            ); \
                                                        } while (0)
#define HMAC(algo, key, klen, data, dlen, res, rlen)    do  { \
                                                            gcry_md_hd_t mdh; \
                                                            gcry_md_open(&mdh, algo, GCRY_MD_FLAG_HMAC); \
                                                            gcry_md_setkey(mdh, key, klen); \
                                                            gcry_md_write(mdh, data, dlen); \
                                                            memcpy(res, gcry_md_read(mdh, algo), \
                                                                gcry_md_get_algo_dlen (algo));  \
                                                            gcry_md_close(mdh); \
                                                        } while (0)
// http://tumblr.spantz.org/post/214737529/the-use-of-do-while-0-in-c-macros
#endif // _GCRYPT_OPENSSL_WRAPPER_H
