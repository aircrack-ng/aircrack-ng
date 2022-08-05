# Aircrack-ng
#
# Copyright (C) 2017-2022 Joseph Benden <joe@benden.us>
#
# Autotool support was written by: Joseph Benden <joe@benden.us>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#
# In addition, as a special exception, the copyright holders give
# permission to link the code of portions of this program with the
# OpenSSL library under certain conditions as described in each
# individual source file, and distribute linked combinations
# including the two.
#
# You must obey the GNU General Public License in all respects
# for all of the code used other than OpenSSL.
#
# If you modify file(s) with this exception, you may extend this
# exception to your dnl version of the file(s), but you are not obligated
# to do so.
#
# If you dnl do not wish to do so, delete this exception statement from your
# version.
#
# If you delete this exception statement from all source files in the
# program, then also delete it here.

SRCS_TEST_EWEP  = %D%/test-encrypt-wep.c
SRCS_TEST_CPMK  = %D%/test-calc-pmk.c
SRCS_TEST_CMIC  = %D%/test-calc-mic.c
SRCS_TEST_CPTK  = %D%/test-calc-ptk.c
SRCS_TEST_DCMP  = %D%/test-decrypt-ccmp.c
SRCS_TEST_ECMP  = %D%/test-encrypt-ccmp.c

test_encrypt_wep_SOURCES = $(SRCS_TEST_EWEP)
test_encrypt_wep_CFLAGS  = $(PTHREAD_CFLAGS) \
						   $(CRYPTO_CFLAGS)
test_encrypt_wep_LDADD   = $(LIBACCRYPTO_LIBS) $(LIBAIRCRACK_LIBS) \
						   $(PTHREAD_LIBS) \
						   $(CRYPTO_LDFLAGS) \
						   $(CRYPTO_LIBS) \
						   $(ZLIB_LIBS)

test_calc_pmk_SOURCES = $(SRCS_TEST_CPMK)
test_calc_pmk_CFLAGS  = $(PTHREAD_CFLAGS) \
						$(CRYPTO_CFLAGS)
test_calc_pmk_LDADD   = $(LIBACCRYPTO_LIBS) $(LIBAIRCRACK_LIBS) \
						$(LIBAIRCRACK_CE_WPA_LIBS) \
						$(PTHREAD_LIBS) \
						$(CRYPTO_LDFLAGS) \
						$(CRYPTO_LIBS) \
						$(ZLIB_LIBS)

test_calc_mic_SOURCES = $(SRCS_TEST_CMIC)
test_calc_mic_CFLAGS  = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
test_calc_mic_LDADD   = $(LIBACCRYPTO_LIBS) $(LIBAIRCRACK_LIBS) \
						$(PTHREAD_LIBS) \
						$(CRYPTO_LDFLAGS) \
						$(CRYPTO_LIBS) \
						$(ZLIB_LIBS)

test_calc_ptk_SOURCES = $(SRCS_TEST_CPTK)
test_calc_ptk_CFLAGS  = $(PTHREAD_CFLAGS) \
						$(CRYPTO_CFLAGS)
test_calc_ptk_LDADD   = $(LIBACCRYPTO_LIBS) $(LIBAIRCRACK_LIBS) \
						$(PTHREAD_LIBS) \
						$(CRYPTO_LDFLAGS) \
						$(CRYPTO_LIBS) \
						$(ZLIB_LIBS)

test_cipher_arcfour_SOURCES = %D%/test-cipher-arcfour.c
test_cipher_arcfour_CFLAGS  = $(PTHREAD_CFLAGS) \
							$(CRYPTO_CFLAGS)
test_cipher_arcfour_LDADD   = $(LIBACCRYPTO_LIBS) $(LIBAIRCRACK_LIBS) \
							$(PTHREAD_LIBS) \
							$(CRYPTO_LDFLAGS) \
							$(CRYPTO_LIBS) \
							$(ZLIB_LIBS)

test_digest_md5_SOURCES = %D%/test-digest-md5.c
test_digest_md5_CFLAGS  = $(PTHREAD_CFLAGS) \
							$(CRYPTO_CFLAGS)
test_digest_md5_LDADD   = $(LIBACCRYPTO_LIBS) $(LIBAIRCRACK_LIBS) \
							$(PTHREAD_LIBS) \
							$(CRYPTO_LDFLAGS) \
							$(CRYPTO_LIBS) \
							$(ZLIB_LIBS)

test_mac_hmac_md5_SOURCES = %D%/test-mac-hmac-md5.c
test_mac_hmac_md5_CFLAGS  = $(PTHREAD_CFLAGS) \
							$(CRYPTO_CFLAGS)
test_mac_hmac_md5_LDADD   = $(LIBACCRYPTO_LIBS) $(LIBAIRCRACK_LIBS) \
							$(PTHREAD_LIBS) \
							$(CRYPTO_LDFLAGS) \
							$(CRYPTO_LIBS) \
							$(ZLIB_LIBS)

test_mac_hmac_sha1_SOURCES = %D%/test-mac-hmac-sha1.c
test_mac_hmac_sha1_CFLAGS  = $(PTHREAD_CFLAGS) \
							$(CRYPTO_CFLAGS)
test_mac_hmac_sha1_LDADD   = $(LIBACCRYPTO_LIBS) $(LIBAIRCRACK_LIBS) \
							$(PTHREAD_LIBS) \
							$(CRYPTO_LDFLAGS) \
							$(CRYPTO_LIBS) \
							$(ZLIB_LIBS)

test_mac_hmac_sha256_SOURCES = %D%/test-mac-hmac-sha256.c
test_mac_hmac_sha256_CFLAGS  = $(PTHREAD_CFLAGS) \
							$(CRYPTO_CFLAGS)
test_mac_hmac_sha256_LDADD   = $(LIBACCRYPTO_LIBS) $(LIBAIRCRACK_LIBS) \
							$(PTHREAD_LIBS) \
							$(CRYPTO_LDFLAGS) \
							$(CRYPTO_LIBS) \
							$(ZLIB_LIBS)

test_digest_sha1_SOURCES = %D%/test-digest-sha1.c
test_digest_sha1_CFLAGS  = $(PTHREAD_CFLAGS) \
							$(CRYPTO_CFLAGS)
test_digest_sha1_LDADD   = $(LIBACCRYPTO_LIBS) $(LIBAIRCRACK_LIBS) \
							$(PTHREAD_LIBS) \
							$(CRYPTO_LDFLAGS) \
							$(CRYPTO_LIBS) \
							$(ZLIB_LIBS)

test_kdf_pbkdf2_hmac_sha1_SOURCES = %D%/test-kdf-pbkdf2-hmac-sha1.c
test_kdf_pbkdf2_hmac_sha1_CFLAGS  = $(PTHREAD_CFLAGS) \
							$(CRYPTO_CFLAGS)
test_kdf_pbkdf2_hmac_sha1_LDADD   = $(LIBACCRYPTO_LIBS) $(LIBAIRCRACK_LIBS) \
							$(PTHREAD_LIBS) \
							$(CRYPTO_LDFLAGS) \
							$(CRYPTO_LIBS) \
							$(ZLIB_LIBS)

test_encrypt_ccmp_SOURCES = $(SRCS_TEST_ECMP)
test_encrypt_ccmp_CFLAGS  = $(PTHREAD_CFLAGS) \
							$(CRYPTO_CFLAGS)
test_encrypt_ccmp_LDADD   = $(LIBACCRYPTO_LIBS) $(LIBAIRCRACK_LIBS) \
							$(PTHREAD_LIBS) \
							$(CRYPTO_LDFLAGS) \
							$(CRYPTO_LIBS) \
							$(ZLIB_LIBS)

test_decrypt_ccmp_SOURCES = $(SRCS_TEST_DCMP)
test_decrypt_ccmp_CFLAGS  = $(PTHREAD_CFLAGS) \
							$(CRYPTO_CFLAGS)
test_decrypt_ccmp_LDADD   = $(LIBACCRYPTO_LIBS) $(LIBAIRCRACK_LIBS) \
							$(PTHREAD_LIBS) \
							$(CRYPTO_LDFLAGS) \
							$(CRYPTO_LIBS) \
							$(ZLIB_LIBS)


TESTS +=	test-encrypt-wep \
			test-calc-pmk \
			test-calc-mic \
			test-calc-ptk \
			test-cipher-arcfour \
			test-digest-md5 \
			test-digest-sha1 \
			test-encrypt-ccmp \
			test-decrypt-ccmp \
			test-mac-hmac-md5 \
			test-mac-hmac-sha1 \
			test-mac-hmac-sha256 \
			test-kdf-pbkdf2-hmac-sha1

check_PROGRAMS +=	test-encrypt-wep \
					test-calc-pmk \
					test-calc-mic \
					test-calc-ptk \
					test-cipher-arcfour \
					test-digest-md5 \
					test-digest-sha1 \
					test-encrypt-ccmp \
					test-decrypt-ccmp \
					test-mac-hmac-md5 \
					test-mac-hmac-sha1 \
					test-mac-hmac-sha256 \
					test-kdf-pbkdf2-hmac-sha1

EXTRA_DIST += %D%/tests.h
