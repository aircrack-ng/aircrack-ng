/*
 * WPA HASH - Cuda Implementations
 *
 * Copyright (C) 2009 Julian Tyler (tylerj@crm114.net)
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */


#include "crypto.h" 
#include <string.h>

/* Cuda Constants */
#define	THREADS_PER_BLOCK	128

/* Size Constants */
#define PMK_SIZE		128
#define BUFFER_SIZE		65

/* Linear Memory Access Macros */
#define pmk_off(x) (pmk + (x * PMK_SIZE * sizeof(unsigned char)))
#define buffer_off(x) (buffer + (x * BUFFER_SIZE * sizeof(unsigned char)))
#define h_buffer_off(x) (h_buffer + (x * BUFFER_SIZE * sizeof(unsigned char)))

/* SHA1 CircularShift */
#define SHA1CircularShift(bits,word) 	((((word) << (bits))) | ((word) >> (32-(bits))))

/* Constants defined in SHA-1 */
#define D_K0	0x5A827999
#define D_K1	0x6ED9EBA1
#define D_K2	0x8F1BBCDC
#define D_K3	0xCA62C1D6

/* Texture Reference */
typedef unsigned int uint;
texture<uint4, 1, cudaReadModeElementType> t_ctx;

/* Cuda SHA1 */
__global__ void cuda_DO_SHA1( uchar *buffer, uchar *pmk, uint pmk_off) 
{
	/* Thread & Block Info */
	const uint p = blockIdx.x * blockDim.x + threadIdx.x;
	const uint tid = threadIdx.x;

	/* Looping Vars */
	uint i, t;

	uint temp;
	uint W[80];

	uint A, B, C, D, E;
	uint h0, h1, h2, h3, h4;

	/* pmk cache */
	__shared__ unsigned char pmk_cache[20 * THREADS_PER_BLOCK];

	/* Load Cache From Device Memory */
	#pragma unroll
	for(t = 0; t < 20; t++)
		pmk_cache[tid * 20 + t] = pmk_off(p)[pmk_off + t];	

	/* End Byte and Padding */
	W[5] = 0x80000000;
	W[6] = 0;
	W[7] = 0;
	W[8] = 0;
	W[9] = 0;
	W[10] = 0;
	W[11] = 0;
	W[12] = 0;
	W[13] = 0;

	/* Size */
	W[14] = 0;
	W[15] = 0x200 + 8*20; 

	/* Load inital values */
	h0 = buffer_off(p)[0] << 24;
	h0 |= buffer_off(p)[1] << 16;
	h0 |= buffer_off(p)[2] << 8;
	h0 |= buffer_off(p)[3];

	h1 = buffer_off(p)[4] << 24;
	h1 |= buffer_off(p)[5] << 16;
	h1 |= buffer_off(p)[6] << 8;
	h1 |= buffer_off(p)[7];

	h2 = buffer_off(p)[8] << 24;
	h2 |= buffer_off(p)[9] << 16;
	h2 |= buffer_off(p)[10] << 8;
	h2 |= buffer_off(p)[11];

	h3 = buffer_off(p)[12] << 24;
	h3 |= buffer_off(p)[13] << 16;
	h3 |= buffer_off(p)[14] << 8;
	h3 |= buffer_off(p)[15];

	h4 = buffer_off(p)[16] << 24;
	h4 |= buffer_off(p)[17] << 16;
	h4 |= buffer_off(p)[18] << 8;
	h4 |= buffer_off(p)[19];

	#pragma unroll 
	for(i = 0; i < 4095; i++) {
    
		/* Inner Context */
		W[0] = h0;
		W[1] = h1;
		W[2] = h2;
		W[3] = h3;
		W[4] = h4;

		h0 = tex1Dfetch(t_ctx, p*3).x;
		h1 = tex1Dfetch(t_ctx, p*3).y;
		h2 = tex1Dfetch(t_ctx, p*3).z;
		h3 = tex1Dfetch(t_ctx, p*3).w;
		h4 = tex1Dfetch(t_ctx, p*3+2).x;
    
		#include "cudacrypto_sha1_process.cuh"

		/* Outer Context */
		W[0] = h0;
		W[1] = h1;
		W[2] = h2;
		W[3] = h3;
		W[4] = h4;

		h0 = tex1Dfetch(t_ctx, p*3+1).x;
		h1 = tex1Dfetch(t_ctx, p*3+1).y;
		h2 = tex1Dfetch(t_ctx, p*3+1).z;
		h3 = tex1Dfetch(t_ctx, p*3+1).w;
		h4 = tex1Dfetch(t_ctx, p*3+2).y;

		#include "cudacrypto_sha1_process.cuh"
 
		/* Cache update */
		pmk_cache[tid * 20 + 0] ^= h0 >> 24 & 0xFF;
		pmk_cache[tid * 20 + 1] ^= h0 >> 16 & 0xFF;
		pmk_cache[tid * 20 + 2] ^= h0 >> 8 & 0xFF;
		pmk_cache[tid * 20 + 3] ^= h0 & 0xFF;

		pmk_cache[tid * 20 + 4] ^= h1 >> 24 & 0xFF;
		pmk_cache[tid * 20 + 5] ^= h1 >> 16 & 0xFF;
 		pmk_cache[tid * 20 + 6] ^= h1 >> 8 & 0xFF;
		pmk_cache[tid * 20 + 7] ^= h1 & 0xFF;

		pmk_cache[tid * 20 + 8] ^= h2 >> 24 & 0xFF;
		pmk_cache[tid * 20 + 9] ^= h2 >> 16 & 0xFF;
		pmk_cache[tid * 20 + 10] ^= h2 >> 8 & 0xFF;
		pmk_cache[tid * 20 + 11] ^= h2 & 0xFF;

		pmk_cache[tid * 20 + 12] ^= h3 >> 24 & 0xFF;
		pmk_cache[tid * 20 + 13] ^= h3 >> 16 & 0xFF;
		pmk_cache[tid * 20 + 14] ^= h3 >> 8 & 0xFF;
		pmk_cache[tid * 20 + 15] ^= h3 & 0xFF;

		pmk_cache[tid * 20 + 16] ^= h4 >> 24 & 0xFF;
		pmk_cache[tid * 20 + 17] ^= h4 >> 16 & 0xFF;
		pmk_cache[tid * 20 + 18] ^= h4 >> 8 & 0xFF;
		pmk_cache[tid * 20 + 19] ^= h4 & 0xFF;
	}

	/* Copy result from Cache to Device Memory */
	#pragma unroll
	for(t = 0; t < 20; t++)
		pmk_off(p)[pmk_off + t] = pmk_cache[tid * 20 + t];
}

extern "C" void cuda_calc_pmk( int count, char **key, char *essid_pre, unsigned char **pmk ) {
	uint i, p, slen;
	char essid[33+4];

	/* Host Memory */
	uchar *h_pmk;
	uchar *h_buffer;
	uint4 *h_ctx;

	/* Device Memory */
        uchar *d_buffer;
        uchar *d_pmk;
	uint4 *d_ctx;

	/* Texture Reference */
	const textureReference* t_ctx_ptr;

	/* Temp SHA Contexts: inner & outer */
	SHA_CTX tmp_ctx_ipad;
	SHA_CTX tmp_ctx_opad;

	/* Allocate Host Memory */
	h_pmk = (uchar *)malloc(sizeof(uchar) * PMK_SIZE * count);
	h_buffer = (uchar *)malloc(sizeof(uchar) * BUFFER_SIZE * count);
	h_ctx = (uint4 *)malloc(sizeof(uint4) * count * 3);	// 10 uints in 3 uint4

	/* Allocate Device Memory */
	cudaMalloc((void **)&d_pmk, sizeof(uchar) * count * 128);
	cudaMalloc((void **)&d_buffer, sizeof(char) * 65 * count);

	/* Setup Texture Reference */
	cudaGetTextureReference(&t_ctx_ptr, "t_ctx");
	cudaMalloc((void **)&d_ctx, count * sizeof(uint4) * 3);
	cudaChannelFormatDesc channelDesc = cudaCreateChannelDesc<uint4>(); 
	cudaBindTexture(0, t_ctx_ptr, d_ctx, &channelDesc, count * sizeof(uint4) * 3);

	/* Setup Block and Grid */
	dim3 dimBlock(THREADS_PER_BLOCK,1);
	dim3 dimGrid((count+dimBlock.x-1)/dimBlock.x, 1);
	
	memset(essid, 0, sizeof(essid));
	memcpy(essid, essid_pre, strlen(essid_pre)+1);
	slen = strlen( essid ) + 4;

	/* setup the inner and outer contexts */
	for(p = 0; p < count; p++) {

		/* Inner Context */
		memset( h_buffer_off(p), 0, sizeof(uchar) * BUFFER_SIZE);
		strncpy( (char *) (h_buffer_off(p)), key[p], BUFFER_SIZE - 1 );

		for( i = 0; i < 64; i++ )
			h_buffer_off(p)[i] ^= 0x36;

		SHA1_Init( &(tmp_ctx_ipad) );
		SHA1_Update( &(tmp_ctx_ipad), h_buffer_off(p), 64 );
		
		h_ctx[3*p].x = tmp_ctx_ipad.h0;
		h_ctx[3*p].y = tmp_ctx_ipad.h1;
		h_ctx[3*p].z = tmp_ctx_ipad.h2;
		h_ctx[3*p].w = tmp_ctx_ipad.h3;
		h_ctx[3*p+2].x = tmp_ctx_ipad.h4;


		/* Outer Context */
		for( i = 0; i < 64; i++ )
			h_buffer_off(p)[i] ^= 0x6A;

		SHA1_Init( &(tmp_ctx_opad) );
		SHA1_Update( &(tmp_ctx_opad), h_buffer_off(p), 64 );

		h_ctx[3*p+1].x = tmp_ctx_opad.h0;
		h_ctx[3*p+1].y = tmp_ctx_opad.h1;
		h_ctx[3*p+1].z = tmp_ctx_opad.h2;
		h_ctx[3*p+1].w = tmp_ctx_opad.h3;
		h_ctx[3*p+2].y = tmp_ctx_opad.h4;

		/* iterate HMAC-SHA1 over itself 8192 times */
		essid[slen - 1] = '\1';
		HMAC(EVP_sha1(), (uchar *)key[p], strlen(key[p]), (uchar*)essid, slen, pmk[p], NULL);
		memcpy( h_buffer_off(p), pmk[p], 20 );
	}
		

	/* Copy from (array of pointers to string) to (linear array of strings) */
	for(i = 0; i < count; i++) {
		uchar *dest =  h_pmk + (i * PMK_SIZE);
		memcpy(dest, pmk[i], PMK_SIZE);
	}

	/* Copy to Device Memory */
	cudaMemcpy(d_ctx, h_ctx, count * sizeof(uint4) * 3, cudaMemcpyHostToDevice);
	cudaMemcpy(d_pmk, h_pmk, count * 128 * sizeof(char), cudaMemcpyHostToDevice);
	cudaMemcpy( d_buffer, h_buffer, count * 65 * sizeof(char), cudaMemcpyHostToDevice);

	/* Do First 4096 iterations of SHA1 */
	cuda_DO_SHA1<<<dimGrid, dimBlock>>>(d_buffer, d_pmk, 0);
	
	/* Copy to result */
	cudaMemcpy(h_pmk, d_pmk, count * 128 * sizeof(char), cudaMemcpyDeviceToHost);

	/* Digest on linear memory */
	for(p = 0; p < count; p++) {
		essid[slen - 1] = '\2';
		HMAC(EVP_sha1(), (uchar *)(key[p]), strlen(key[p]), (uchar*)essid, slen, (h_pmk + (PMK_SIZE * p)) + 20, NULL);
		memcpy( h_buffer_off(p), (h_pmk + (PMK_SIZE * p)) + 20, 20 );
	}

	/* Copy back to device memory */
	cudaMemcpy(d_pmk, h_pmk, count * 128 * sizeof(char), cudaMemcpyHostToDevice);
	cudaMemcpy( d_buffer, h_buffer, count * 65 * sizeof(char), cudaMemcpyHostToDevice);

	/* Do Second 4096 iterations of SHA1 */
	cuda_DO_SHA1<<<dimGrid, dimBlock>>>(d_buffer, d_pmk, 20);

	/* Copy result from device memory */
	cudaMemcpy(h_pmk, d_pmk, count * 128 * sizeof(char), cudaMemcpyDeviceToHost);

	/* Convert result to (array of pointers to string) */
	for(i = 0; i < count; i++) {
		uchar *src = h_pmk + (i * PMK_SIZE);
		memcpy(pmk[i], src, PMK_SIZE);
	}


	/* Free Device Memory */
	cudaFree(d_ctx);
	cudaFree(d_pmk);
	cudaFree(d_buffer);

	/* Free Host Memory */
	free(h_pmk);
	free(h_buffer);
	free(h_ctx);
}

extern "C" int cuda_getblocksize()
{
	int device_count;
	int blocksize = 0;
	cudaDeviceProp device_prop;
	
	cudaGetDeviceCount(&device_count);

	/* No Cuda Device Found */
	if(device_count == 0)
		return 0;

        cudaGetDeviceProperties(&device_prop, 0);

	/* Limited By Shared Memory */
	/* 5 Blocks per MP */
	/* (2588+28) * 5 ==  13080 < (16384 shared memory of per MP)*/

	blocksize = THREADS_PER_BLOCK * 5 * device_prop.multiProcessorCount;

	return blocksize;
}
