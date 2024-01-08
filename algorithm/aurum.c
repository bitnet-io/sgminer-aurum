#include "config.h"
#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <stdlib.h>
#include <string.h>  
#include <stdio.h> 

#define F0(i)  {               \
    i0 = ((i) - 0*4)  & mask1; \
    i1 = ((i) - 2*4)  & mask1; \
    i2 = ((i) - 3*4)  & mask1; \
    i3 = ((i) - 7*4)  & mask1; \
    i4 = ((i) - 13*4) & mask1; \
    S[i0+1] = ((S[i1+0] ^ S[i2+0]) + S[i3+0]) ^ S[i4+0];         \
    S[i0+2] = ((S[i1+1] ^ S[i2+1]) + S[i3+1]) ^ S[i4+1];         \
    S[i0+3] = ((S[i1+2] ^ S[i2+2]) + S[i3+2]) ^ S[i4+2];         \
    S[i0+0] = ((S[i1+3] ^ S[i2+3]) + S[i3+3]) ^ S[i4+3];         \
    S[i0+0] = (S[i0+0] << 17) | (S[i0+0] >> 47);  \
    S[i0+1] = (S[i0+1] << 17) | (S[i0+1] >> 47);  \
    S[i0+2] = (S[i0+2] << 17) | (S[i0+2] >> 47);  \
    S[i0+3] = (S[i0+3] << 17) | (S[i0+3] >> 47);  \
}

#define F(i)  {                \
    i0 = ((i) - 0*4)  & mask1; \
    i1 = ((i) - 2*4)  & mask1; \
    i2 = ((i) - 3*4)  & mask1; \
    i3 = ((i) - 7*4)  & mask1; \
    i4 = ((i) - 13*4) & mask1; \
    S[i0+0] += ((S[i1+0] ^ S[i2+0]) + S[i3+0]) ^ S[i4+0];         \
    S[i0+1] += ((S[i1+1] ^ S[i2+1]) + S[i3+1]) ^ S[i4+1];         \
    S[i0+2] += ((S[i1+2] ^ S[i2+2]) + S[i3+2]) ^ S[i4+2];         \
    S[i0+3] += ((S[i1+3] ^ S[i2+3]) + S[i3+3]) ^ S[i4+3];         \
    temp = S[i0+3];         \
    S[i0+3] = S[i0+2];      \
    S[i0+2] = S[i0+1];      \
    S[i0+1] = S[i0+0];      \
    S[i0+0] = temp;         \
    S[i0+0] = (S[i0+0] << 17) | (S[i0+0] >> 47);  \
    S[i0+1] = (S[i0+1] << 17) | (S[i0+1] >> 47);  \
    S[i0+2] = (S[i0+2] << 17) | (S[i0+2] >> 47);  \
    S[i0+3] = (S[i0+3] << 17) | (S[i0+3] >> 47);  \
}

#define G(i,random_number)  {                                                       \
    index_global = ((random_number >> 16) & mask) << 2;                             \
    for (j = 0; j < 128; j = j+4)                                                   \
    {                                                                               \
        F(i+j);                                                                     \
        index_global   = (index_global + 4) & mask1;                                      \
        index_local    = (((i + j) >> 2) - 0x1000 + (random_number & 0x1fff)) & mask;     \
        index_local    = index_local << 2;                                                \
        S[i0+0]       += (S[index_local+0] << 1);                                   \
        S[i0+1]       += (S[index_local+1] << 1);                                   \
        S[i0+2]       += (S[index_local+2] << 1);                                   \
        S[i0+3]       += (S[index_local+3] << 1);                                   \
        S[index_local+0] += (S[i0+0] << 2); \
        S[index_local+1] += (S[i0+1] << 2); \
        S[index_local+2] += (S[i0+2] << 2); \
        S[index_local+3] += (S[i0+3] << 2); \
        S[i0+0]       += (S[index_global+0] << 1);                                   \
        S[i0+1]       += (S[index_global+1] << 1);                                   \
        S[i0+2]       += (S[index_global+2] << 1);                                   \
        S[i0+3]       += (S[index_global+3] << 1);                                   \
        S[index_global+0] += (S[i0+0] << 3); \
        S[index_global+1] += (S[i0+1] << 3); \
        S[index_global+2] += (S[i0+2] << 3); \
        S[index_global+3] += (S[i0+3] << 3); \
        random_number += (random_number << 2);                                      \
        random_number  = (random_number << 19) ^ (random_number >> 45)  ^ 3141592653589793238ULL;   \
    }                                                                               \
}

#define H(i, random_number)  {                                                      \
    index_global = ((random_number >> 16) & mask) << 2;                             \
    for (j = 0; j < 128; j = j+4)                                                   \
    {                                                                               \
        F(i+j);                                                                     \
        index_global   = (index_global + 4) & mask1;                                      \
        index_local    = (((i + j) >> 2) - 0x1000 + (random_number & 0x1fff)) & mask;     \
        index_local    = index_local << 2;                                                \
        S[i0+0]       += (S[index_local+0] << 1);                                   \
        S[i0+1]       += (S[index_local+1] << 1);                                   \
        S[i0+2]       += (S[index_local+2] << 1);                                   \
        S[i0+3]       += (S[index_local+3] << 1);                                   \
        S[index_local+0] += (S[i0+0] << 2); \
        S[index_local+1] += (S[i0+1] << 2); \
        S[index_local+2] += (S[i0+2] << 2); \
        S[index_local+3] += (S[i0+3] << 2); \
        S[i0+0]       += (S[index_global+0] << 1);                                   \
        S[i0+1]       += (S[index_global+1] << 1);                                   \
        S[i0+2]       += (S[index_global+2] << 1);                                   \
        S[i0+3]       += (S[index_global+3] << 1);                                   \
        S[index_global+0] += (S[i0+0] << 3); \
        S[index_global+1] += (S[i0+1] << 3); \
        S[index_global+2] += (S[i0+2] << 3); \
        S[index_global+3] += (S[i0+3] << 3); \
        random_number  = S[i3];              \
    }                                        \
}

/*
 * Encode a length len/4 vector of (uint32_t) into a length len vector of
 * (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
 */
static inline void
be32enc_vect(uint32_t *dst, const uint32_t *src, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < len; i++)
		dst[i] = htobe32(src[i]);
}

static inline void aurum_hash(void *state, const void *input)
{
    unsigned long long i,j,k,temp;         
    unsigned long long i0,i1,i2,i3,i4;
    unsigned long long *S; 
    unsigned long long random_number, index_global, index_local; 
    unsigned long long state_size, mask, mask1, mask2;  

    //Step 1: Initialize the state S          
    state_size = 1ULL << 21;
    S = (unsigned long long *)malloc(state_size);          
    mask  = (1ULL << 16) - 1;  // mask is used for modulation: modulo size_size/32; 
    mask1 = (1ULL << 18) - 1;   // mask is used for modulation: modulo size_size/8; 

    for (i = 0; i < 80; i++)((unsigned char*)S)[i] = ((unsigned char*)input)[i];      //header
    for (i = 0; i < 4; i++) ((unsigned char*)S)[80+i] = ((unsigned char*)input)[76+i]; //salt/nonce
    for (i = 80+4; i < 384; i++) ((unsigned char*)S)[i] = 0;
    ((unsigned char*)S)[384] = 80 & 0xff;         // load password length (in bytes) into S;
    ((unsigned char*)S)[385] = (80 >> 8) & 0xff;  // load password length (in bytes) into S;
    ((unsigned char*)S)[386] = 4;              // load salt length (in bytes) into S;
    ((unsigned char*)S)[387] = 32 & 0xff;        // load output length (in bytes into S)
    ((unsigned char*)S)[388] = (32 >> 8) & 0xff; // load output length (in bytes into S) 
    ((unsigned char*)S)[389] = 0; 
    ((unsigned char*)S)[390] = 0; 
    ((unsigned char*)S)[391] = 0;

    ((unsigned char*)S)[392] = 1;
    ((unsigned char*)S)[393] = 1;
    for (i = 394; i < 416; i++) ((unsigned char*)S)[i] = ((unsigned char*)S)[i-1] + ((unsigned char*)S)[i-2];    
 
    //Step 3: Expand the data into the whole state  
    for (i = 13*4; i < (1ULL << (10+8)); i=i+4)  F0(i);  

    //Step 4: Update the state using function G  
    random_number = 123456789ULL;    
    for (i = 0; i < (1ULL << (9+8+2)); i=i+128) G(i,random_number);  

    //Step 5: Update the state using function H     
    for (i = 1ULL << (9+8+2);  i < (1ULL << (10+8+2)); i=i+128)  H(i,random_number);

    //Step 6: Update the state using function F 
    for (i = 0; i < (1ULL << (10+8)); i=i+4)  F(i);       

    //Step 7: Generate the output   
    memcpy(state, ((unsigned char*)S)+state_size-32, 32);
    memset(S, 0, state_size);  // clear the memory 
    free(S);          // free the memory

    return 0;
}

static const uint32_t diff1targ = 0x0000ffff;

/* Used externally as confirmation of correct OCL code */
int aurum_test(unsigned char *pdata, const unsigned char *ptarget, uint32_t nonce)
{
	uint32_t tmp_hash7, Htarg = le32toh(((const uint32_t *)ptarget)[7]);
	uint32_t data[20], ohash[8];

	be32enc_vect(data, (const uint32_t *)pdata, 19);
	data[19] = htobe32(nonce);
	aurum_hash(ohash, data);
	tmp_hash7 = be32toh(ohash[7]);

	applog(LOG_DEBUG, "htarget %08lx diff1 %08lx hash %08lx",
				(long unsigned int)Htarg,
				(long unsigned int)diff1targ,
				(long unsigned int)tmp_hash7);
	if (tmp_hash7 > diff1targ)
		return -1;
	if (tmp_hash7 > Htarg)
		return 0;
	return 1;
}

void aurum_regenhash(struct work *work)
{
        uint32_t data[20];
        uint32_t *nonce = (uint32_t *)(work->data + 76);
        uint32_t *ohash = (uint32_t *)(work->hash);

        be32enc_vect(data, (const uint32_t *)work->data, 19);
        data[19] = htobe32(*nonce);
        aurum_hash(ohash, data);
}

bool scanhash_aurum(struct thr_info *thr, const unsigned char __maybe_unused *pmidstate,
		     unsigned char *pdata, unsigned char __maybe_unused *phash1,
		     unsigned char __maybe_unused *phash, const unsigned char *ptarget,
		     uint32_t max_nonce, uint32_t *last_nonce, uint32_t n)
{
	uint32_t *nonce = (uint32_t *)(pdata + 76);
	uint32_t data[20];
	uint32_t tmp_hash7;
	uint32_t Htarg = le32toh(((const uint32_t *)ptarget)[7]);
	bool ret = false;

	be32enc_vect(data, (const uint32_t *)pdata, 19);

	while(1) {
		uint32_t ostate[8];

		*nonce = ++n;
		data[19] = (n);
		aurum_hash(ostate, data);
		tmp_hash7 = (ostate[7]);

		applog(LOG_INFO, "data7 %08lx",
					(long unsigned int)data[7]);

		if (unlikely(tmp_hash7 <= Htarg)) {
			((uint32_t *)pdata)[19] = htobe32(n);
			*last_nonce = n;
			ret = true;
			break;
		}

		if (unlikely((n >= max_nonce) || thr->work_restart)) {
			*last_nonce = n;
			break;
		}
	}

	return ret;
}



