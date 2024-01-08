/*
 * Aurum kernel implementation.
 */

#ifndef AURUM_CL
#define AURUM_CL

#if __ENDIAN_LITTLE__
#define SPH_LITTLE_ENDIAN 1
#else
#define SPH_BIG_ENDIAN 1
#endif

#define SPH_UPTR sph_u64

typedef unsigned int sph_u32;
typedef int sph_s32;
#ifndef __OPENCL_VERSION__
typedef unsigned long long sph_u64;
typedef long long sph_s64;
#else
typedef unsigned long sph_u64;
typedef long sph_s64;
#endif

#define SPH_64 1
#define SPH_64_TRUE 1

#define SPH_C32(x)    ((sph_u32)(x ## U))
#define SPH_T32(x) (as_uint(x))
#define SPH_ROTL32(x, n) rotate(as_uint(x), as_uint(n))
#define SPH_ROTR32(x, n)   SPH_ROTL32(x, (32 - (n)))

#define SPH_C64(x)    ((sph_u64)(x ## UL))
#define SPH_T64(x) (as_ulong(x))
#define SPH_ROTL64(x, n) rotate(as_ulong(x), (n) & 0xFFFFFFFFFFFFFFFFUL)
#define SPH_ROTR64(x, n)   SPH_ROTL64(x, (64 - (n)))

#define SWAP4(x) as_uint(as_uchar4(x).wzyx)
#define SWAP8(x) as_ulong(as_uchar8(x).s76543210)

#if SPH_BIG_ENDIAN
  #define DEC64E(x) (x)
  #define DEC64BE(x) (*(const __global sph_u64 *) (x));
#else
  #define DEC64E(x) SWAP8(x)
  #define DEC64BE(x) SWAP8(*(const __global sph_u64 *) (x));
#endif

#define SHL(x, n) ((x) << (n))
#define SHR(x, n) ((x) >> (n))

//begin pomelo macros

#define MAP(X) ((X)*GID+gid)
#define MAPCH(X) (((X)/8*GID+gid)*8+(X)%8)

#define F0(i)  {               \
    i0 = ((i) - 0*4)  & mask1; \
    i1 = ((i) - 2*4)  & mask1; \
    i2 = ((i) - 3*4)  & mask1; \
    i3 = ((i) - 7*4)  & mask1; \
    i4 = ((i) - 13*4) & mask1; \
    S[MAP(i0+1)] = ((S[MAP(i1+0)] ^ S[MAP(i2+0)]) + S[MAP(i3+0)]) ^ S[MAP(i4+0)];         \
    S[MAP(i0+2)] = ((S[MAP(i1+1)] ^ S[MAP(i2+1)]) + S[MAP(i3+1)]) ^ S[MAP(i4+1)];         \
    S[MAP(i0+3)] = ((S[MAP(i1+2)] ^ S[MAP(i2+2)]) + S[MAP(i3+2)]) ^ S[MAP(i4+2)];         \
    S[MAP(i0+0)] = ((S[MAP(i1+3)] ^ S[MAP(i2+3)]) + S[MAP(i3+3)]) ^ S[MAP(i4+3)];         \
    S[MAP(i0+0)] = (S[MAP(i0+0)] << 17) | (S[MAP(i0+0)] >> 47);  \
    S[MAP(i0+1)] = (S[MAP(i0+1)] << 17) | (S[MAP(i0+1)] >> 47);  \
    S[MAP(i0+2)] = (S[MAP(i0+2)] << 17) | (S[MAP(i0+2)] >> 47);  \
    S[MAP(i0+3)] = (S[MAP(i0+3)] << 17) | (S[MAP(i0+3)] >> 47);  \
}

#define F(i)  {                \
    i0 = ((i) - 0*4)  & mask1; \
    i1 = ((i) - 2*4)  & mask1; \
    i2 = ((i) - 3*4)  & mask1; \
    i3 = ((i) - 7*4)  & mask1; \
    i4 = ((i) - 13*4) & mask1; \
    S[MAP(i0+0)] += ((S[MAP(i1+0)] ^ S[MAP(i2+0)]) + S[MAP(i3+0)]) ^ S[MAP(i4+0)];         \
    S[MAP(i0+1)] += ((S[MAP(i1+1)] ^ S[MAP(i2+1)]) + S[MAP(i3+1)]) ^ S[MAP(i4+1)];         \
    S[MAP(i0+2)] += ((S[MAP(i1+2)] ^ S[MAP(i2+2)]) + S[MAP(i3+2)]) ^ S[MAP(i4+2)];         \
    S[MAP(i0+3)] += ((S[MAP(i1+3)] ^ S[MAP(i2+3)]) + S[MAP(i3+3)]) ^ S[MAP(i4+3)];         \
    temp = S[MAP(i0+3)];         \
    S[MAP(i0+3)] = S[MAP(i0+2)];      \
    S[MAP(i0+2)] = S[MAP(i0+1)];      \
    S[MAP(i0+1)] = S[MAP(i0+0)];      \
    S[MAP(i0+0)] = temp;         \
    S[MAP(i0+0)] = (S[MAP(i0+0)] << 17) | (S[MAP(i0+0)] >> 47);  \
    S[MAP(i0+1)] = (S[MAP(i0+1)] << 17) | (S[MAP(i0+1)] >> 47);  \
    S[MAP(i0+2)] = (S[MAP(i0+2)] << 17) | (S[MAP(i0+2)] >> 47);  \
    S[MAP(i0+3)] = (S[MAP(i0+3)] << 17) | (S[MAP(i0+3)] >> 47);  \
}

#define G(i,random_number)  {                                                       \
    index_global = ((random_number >> 16) & mask) << 2;                             \
    for (j = 0; j < 128; j = j+4)                                                   \
    {                                                                               \
        F(i+j);                                                                     \
        index_global   = (index_global + 4) & mask1;                                      \
        index_local    = (((i + j) >> 2) - 0x1000 + (random_number & 0x1fff)) & mask;     \
        index_local    = index_local << 2;                                                \
        S[MAP(i0+0)]       += (S[MAP(index_local+0)] << 1);                                   \
        S[MAP(i0+1)]       += (S[MAP(index_local+1)] << 1);                                   \
        S[MAP(i0+2)]       += (S[MAP(index_local+2)] << 1);                                   \
        S[MAP(i0+3)]       += (S[MAP(index_local+3)] << 1);                                   \
        S[MAP(index_local+0)] += (S[MAP(i0+0)] << 2); \
        S[MAP(index_local+1)] += (S[MAP(i0+1)] << 2); \
        S[MAP(index_local+2)] += (S[MAP(i0+2)] << 2); \
        S[MAP(index_local+3)] += (S[MAP(i0+3)] << 2); \
        S[MAP(i0+0)]       += (S[MAP(index_global+0)] << 1);                                   \
        S[MAP(i0+1)]       += (S[MAP(index_global+1)] << 1);                                   \
        S[MAP(i0+2)]       += (S[MAP(index_global+2)] << 1);                                   \
        S[MAP(i0+3)]       += (S[MAP(index_global+3)] << 1);                                   \
        S[MAP(index_global+0)] += (S[MAP(i0+0)] << 3); \
        S[MAP(index_global+1)] += (S[MAP(i0+1)] << 3); \
        S[MAP(index_global+2)] += (S[MAP(i0+2)] << 3); \
        S[MAP(index_global+3)] += (S[MAP(i0+3)] << 3); \
        random_number += (random_number << 2);                                      \
        random_number  = (random_number << 19) ^ (random_number >> 45)  ^ 3141592653589793238UL;   \
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
        S[MAP(i0+0)]       += (S[MAP(index_local+0)] << 1);                                   \
        S[MAP(i0+1)]       += (S[MAP(index_local+1)] << 1);                                   \
        S[MAP(i0+2)]       += (S[MAP(index_local+2)] << 1);                                   \
        S[MAP(i0+3)]       += (S[MAP(index_local+3)] << 1);                                   \
        S[MAP(index_local+0)] += (S[MAP(i0+0)] << 2); \
        S[MAP(index_local+1)] += (S[MAP(i0+1)] << 2); \
        S[MAP(index_local+2)] += (S[MAP(i0+2)] << 2); \
        S[MAP(index_local+3)] += (S[MAP(i0+3)] << 2); \
        S[MAP(i0+0)]       += (S[MAP(index_global+0)] << 1);                                   \
        S[MAP(i0+1)]       += (S[MAP(index_global+1)] << 1);                                   \
        S[MAP(i0+2)]       += (S[MAP(index_global+2)] << 1);                                   \
        S[MAP(i0+3)]       += (S[MAP(index_global+3)] << 1);                                   \
        S[MAP(index_global+0)] += (S[MAP(i0+0)] << 3); \
        S[MAP(index_global+1)] += (S[MAP(i0+1)] << 3); \
        S[MAP(index_global+2)] += (S[MAP(i0+2)] << 3); \
        S[MAP(index_global+3)] += (S[MAP(i0+3)] << 3); \
        random_number  = S[MAP(i3)];              \
    }                                        \
}

//finish pomelo macros

#define T_COST 2
#define M_COST 8

__kernel void init()
{
    // The following variable is in private memory by default
    state_size = 1UL << (13 + M_COST);
    unsigned long *S = malloc(state_size);
}

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void search(__global unsigned char* block,
                     volatile __global uint* output,
                     const ulong target)
{
  uint gid = get_global_id(0);
	uint GID = get_global_size(0);

	unsigned long i, j, temp, y;
	unsigned long i0, i1, i2, i3, i4;
	unsigned long random_number, index_global, index_local;
	unsigned long state_size, mask, mask1;
  init();
  
	size_t outlen = 32;
  size_t saltlen = 4;
	uint base = 0;
  uint inlen = 80;

	//output += gid * BINARY_SIZE;

	//in += base;

	if (inlen > 256 || saltlen > 64 || outlen > 256)
		return;

	state_size = 1UL << (13 + M_COST);	

	mask = (1UL << (8 + M_COST)) - 1;	// mask is used for modulation: modulo size_size/32; 
	mask1 = (1UL << (10 + M_COST)) - 1;	// mask is used for modulation: modulo size_size/8;

	//Step 2: Load the password, salt, input/output sizes into the state S
	for (i = 0; i < inlen; i++)
		((__global unsigned char *)S)[MAPCH(i)] = block[i];	// load password into S
	for (i = 0; i < saltlen; i++)
		((__global unsigned char *)S)[MAPCH(inlen + i)] = block[i+76];	// load salt into S
	for (i = inlen + saltlen; i < 384; i++)
		((__global unsigned char *)S)[MAPCH(i)] = 0;
	((__global unsigned char *)S)[MAPCH(384)] = inlen & 0xff;	// load password length (in bytes) into S;
	((__global unsigned char *)S)[MAPCH(385)] = (inlen >> 8) & 0xff;	// load password length (in bytes) into S;
	((__global unsigned char *)S)[MAPCH(386)] = saltlen;	// load salt length (in bytes) into S;
	((__global unsigned char *)S)[MAPCH(387)] = outlen & 0xff;	// load output length (in bytes into S)
	((__global unsigned char *)S)[MAPCH(388)] = (outlen >> 8) & 0xff;	// load output length (in bytes into S) 
	((__global unsigned char *)S)[MAPCH(389)] = 0;
	((__global unsigned char *)S)[MAPCH(390)] = 0;
	((__global unsigned char *)S)[MAPCH(391)] = 0;

	((__global unsigned char *)S)[MAPCH(392)] = 1;
	((__global unsigned char *)S)[MAPCH(393)] = 1;


	for (i = 394; i < 416; i++)
		((__global unsigned char *)S)[MAPCH(i)] =
		    ((__global unsigned char *)S)[MAPCH(i - 1)] + ((__global unsigned char *)S)[MAPCH(i - 2)];


	//Step 3: Expand the data into the whole state  
	y = (1UL << (10 + M_COST));
	for (i = 13 * 4; i < y; i = i + 4)
		F0(i);


	//Step 4: Update the state using function G  
	random_number = 123456789UL;
	for (i = 0; i < (1UL << (9 + M_COST + T_COST)); i = i + 128)
		G(i, random_number);

	//Step 5: Update the state using function H     
	for (i = 1UL << (9 + M_COST + T_COST);
	    i < (1UL << (10 + M_COST + T_COST)); i = i + 128)
		H(i, random_number);

	//Step 6: Update the state using function F 
	for (i = 0; i < (1UL << (10 + M_COST)); i = i + 4)
		F(i);

	//Step 7: Generate the output
	for (i = 0; i < outlen; i++) {
		output[i + 1] = ((__global unsigned char *)S)[MAPCH(state_size - outlen + i)];
	}
	output[0] = (char)outlen;
}

#endif // AURUM_CL
