#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

void matchID()
{
  size_t v1; // eax
  int v2; // esi
  size_t v3; // eax
  time_t timer; // [esp+Ch] [ebp-2Ch]
  char s[15]; // [esp+10h] [ebp-28h]
  char v7; // [esp+1Fh] [ebp-19h]
  int v8; // [esp+20h] [ebp-18h]
  struct tm *v9; // [esp+24h] [ebp-14h]
  int v10; // [esp+28h] [ebp-10h]
  int i; // [esp+2Ch] [ebp-Ch]

  memset(s, 0, 0xFu);
  v10 = 10;
  time(&timer);
  v9 = localtime(&timer);
  srand(v9->tm_sec);
  for ( i = 0; i < v10; ++i )
  {
    v8 = rand() % 26;
    if ( v8 & 1 )
    {
      v7 = v8 + 97;
      v2 = (char)(v8 + 97);
      v3 = strlen(s);
      snprintf(&s[v3], 0xFu, "%c", v2);
    }
    else
    {
      v1 = strlen(s);
      snprintf(&s[v1], 0xFu, "%d", v8);
    }
  }
  /* return strcmp(s1, s) == 0; */
  puts(s);
}

int main()
{
	matchID();
	return 0;
}
