// gcc set_canary.c -g -o set_canary
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
/* #include <linux/types.h> */
/* # define unsigned __int8 __uint8_t */
/* # define unsigned __int16 __uint16_t */
/* # define unsigned __int16 __uint64_t */
# define _DWORD uint32_t
# define getenv(NULL) 0
# define LODWORD(x)  (*((_DWORD*)&(x)))  // low dword

__uint64_t set_canary()
{
  int v0; // ebx
  __uint64_t v1; // rbx
  int v2; // er12
  __uint64_t v3; // ST08_8
  time_t v4; // rbx
  __uint64_t v5; // ST08_8
  time_t v6; // ST08_8
  time_t v7; // ST08_8
  __uint64_t result; // rax

  time(0LL);
  time(0LL);
  v0 = time(0LL) >> 24;
  v1 = (__uint64_t)(__uint8_t)(v0 ^ (__uint64_t)getenv(NULL)) << 24;
  v2 = time(0LL) >> 16;
  v3 = v1 + ((__uint64_t)(__uint8_t)(v2 ^ (__uint64_t)getenv(NULL)) << 16);
  v4 = time(0LL) >> 8;
  v5 = (__uint16_t)((((__uint16_t)v4 ^ (__uint16_t)time(0LL)) << 8) & 0xFF00) + v3;
  v6 = ((time(0LL) << 32) & 0xFF00000000LL) + v5;
  v7 = time(0LL) + v6;
  LODWORD(v4) = time(0LL) >> 24;
  LODWORD(v4) = (time(0LL) >> 16) + v4;
  LODWORD(v4) = (time(0LL) >> 8) + v4;
  result = ((__uint64_t)(__uint8_t)(v4 + time(0LL)) << 40) + v7;
  /* __writefsqword(0x28u, result); */
  return result;
}

int main()
{
	printf("0x%lx\n", set_canary());
}
