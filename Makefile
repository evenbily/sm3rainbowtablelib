
alglib:
	gcc -Wall -O3 -shared -fPIC alglib1.c SM3.c -lcrypto -o alglib1.so
	strip alglib1.so
