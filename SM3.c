#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "SM3.h"

#define ROTATE_LEFT(x,s,n) ((x)<<(n)|((x)>>((s)-(n))))

#define UCHAR2ULONG(l,c)					\
{											\
	(l) = ((unsigned long) (c)[0] << 24 )	\
		| ((unsigned long) (c)[1] << 16 )	\
		| ((unsigned long) (c)[2] <<  8 )	\
		| ((unsigned long) (c)[3]		);	\
}

#define ULONG2UCHAR(l,c)					\
{											\
	(c)[0] = (unsigned char) ( (l) >> 24 );	\
	(c)[1] = (unsigned char) ( (l) >> 16 );	\
	(c)[2] = (unsigned char) ( (l) >>  8 );	\
	(c)[3] = (unsigned char) ( (l)		 );	\
}

#define FF_15(X,Y,Z) ((X)^(Y)^(Z))
#define FF_63(X,Y,Z) (((X)&(Y))|((Y)&(Z))|((Z)&(X)))

#define GG_15(X,Y,Z) ((X)^(Y)^(Z))
#define GG_63(X,Y,Z) (((X)&(Y))|((~(X))&(Z)))

static const unsigned int IV[8] = { 0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e };

unsigned long T_15 = 0x79cc4519;
unsigned long T_63 = 0x7a879d8a;

unsigned long P0(unsigned long X) {
	unsigned long output;
	output = X
		^ ROTATE_LEFT(X, 32, 9)
		^ ROTATE_LEFT(X, 32, 17);
	return output;
}

unsigned long P1(unsigned long X) {
	unsigned long output;
	output = X
		^ ROTATE_LEFT(X, 32, 15)
		^ ROTATE_LEFT(X, 32, 23);
	return output;
}

unsigned char* pack(unsigned char* input,
					unsigned long long length, 
					unsigned long long *length_new) {

	unsigned long k, rem, i;
	unsigned long long bitLength;
	unsigned char clength[8];
	unsigned char* output;
	bitLength = length * 8;
	rem = (length + 1) % 64;
	k = (rem > 56) ? (120 - rem) : (56 - rem);
	*length_new = length + k + 9;
	for (i = 0; i < 8; i++) {
		clength[i] = (unsigned char)((bitLength >> (56 - 8 * i)) & 0xff);
	}
	
	output = (unsigned char*)malloc(sizeof(char)*(*length_new));
	memcpy(output, input, length);
	output[length] = 0x80;
	memset((void*)(output + length + 1), 0, k);
	memcpy(output + length + 1 + k, clength, 8);

	return output;
}

void expand(unsigned long B[16], unsigned long W[68], unsigned long _W[64]) {
	int i = 0;
	for (; i < 16; i++)
		W[i] = B[i];
	for (; i < 68; i++)
		W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROTATE_LEFT(W[i - 3], 32, 15)) ^ ROTATE_LEFT(W[i - 13], 32, 7) ^ W[i - 6];
	for (i = 0; i < 64; i++)
		_W[i] = W[i] ^ W[i + 4];
}

void CF(unsigned long V[8], unsigned long B[16], unsigned long output[8]) {
	int i = 0;
	unsigned long SS1, SS2, TT1, TT2;
	unsigned long W[68];
	unsigned long _W[64];

	expand(B, W, _W);
	
	memcpy(output, V, 32);

	for (; i < 16; i++) {
		SS1 = ROTATE_LEFT(output[0], 32, 12) + output[4] + ROTATE_LEFT(T_15, 32, i);
		SS1 = ROTATE_LEFT(SS1, 32, 7);
		SS2 = SS1^ROTATE_LEFT(output[0], 32, 12);
		TT1 = FF_15(output[0], output[1], output[2]) + output[3] + SS2 + _W[i];
		TT2 = GG_15(output[4], output[5], output[6]) + output[7] + SS1 + W[i];
		output[3] = output[2];
		output[2] = ROTATE_LEFT(output[1], 32, 9);
		output[1] = output[0];
		output[0] = TT1;
		output[7] = output[6];
		output[6] = ROTATE_LEFT(output[5], 32, 19);
		output[5] = output[4];
		output[4] = P0(TT2);
	}

	for (; i < 64; i++) {
		SS1 = ROTATE_LEFT(output[0], 32, 12) + output[4] + ROTATE_LEFT(T_63, 32, i);
		SS1 = ROTATE_LEFT(SS1, 32, 7);
		SS2 = SS1^ROTATE_LEFT(output[0], 32, 12);
		TT1 = FF_63(output[0], output[1], output[2]) + output[3] + SS2 + _W[i];
		TT2 = GG_63(output[4], output[5], output[6]) + output[7] + SS1 + W[i];
		output[3] = output[2];
		output[2] = ROTATE_LEFT(output[1], 32, 9);
		output[1] = output[0];
		output[0] = TT1;
		output[7] = output[6];
		output[6] = ROTATE_LEFT(output[5], 32, 19);
		output[5] = output[4];
		output[4] = P0(TT2);
	}

	for (i = 0; i < 8; i++) {
		output[i] ^= V[i];
	}
}

void SM3(unsigned char* input, 
	unsigned long long length, //length <= 15
	unsigned char output[32]) 
{
	unsigned long long length_new, n, i, j;
	unsigned long V[8];
	unsigned long B[16];
	unsigned long Vnext[8];
	unsigned char *mes_new;

	mes_new = pack(input, length, &length_new);
	n = length_new / 64;

	for (i = 0; i < 8; i++)
		V[i] = IV[i];

	for (i = 0; i < n; i++) {
		for (j = 0; j < 16; j++)
			UCHAR2ULONG(B[j], mes_new + 64 * i + 4 * j);
		CF(V, B, Vnext);
		for (j = 0; j < 8; j++)
			V[j] = Vnext[j];
	}

	for (i = 0; i < 8; i++) {
		ULONG2UCHAR(V[i], output + 4 * i);
	}
}