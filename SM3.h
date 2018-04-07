#pragma once

#ifdef _WIN32
#ifdef __cplusplus
extern "C"
#endif
#endif
void
#ifdef _WIN32
__stdcall
#endif


SM3(
	unsigned char* input, 
	unsigned long long length,   //length <= 15
	unsigned char output[32]);

//length is in byte