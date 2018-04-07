
cl /LD /O2 alglib1.c SM3.c /link /EXPORT:HashAlgorithms

@del *.obj
@del *.exp
@del *.lib
