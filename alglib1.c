
#include "SM3.h"

#define MIN_HASH_LEN		8
#define MAX_HASH_LEN		64

struct HashAlgorithmEntry
{
	char			*szName;
	void			*pHashAlgorithm;
	unsigned int	uHashLen;		// MIN_HASH_LEN <= uHashLen <= MAX_HASH_LEN
	unsigned int	uPlaintextLenMin;
	unsigned int	uPlaintextLenMax;
};

struct HashAlgorithmEntry HashAlgorithms[] = {
//	{(char *)"lm",						(void *)LM,						8,		0,	7},
//	{(char *)"ntlm",					(void *)NTLM,					16,		0,	15},
	{(char *)"SM3",					(void *)SM3,					32,		0,	15},
//	{(char *)"sha1",					(void *)SHA1,					20,		0,	20},
//	{(char *)"sha256",					(void *)SHA256,					32,		0,	20},

	{(char *)0,							(void *)0,						0,		0,	0},
};
