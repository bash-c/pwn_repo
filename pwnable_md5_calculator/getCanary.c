#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[])
{
    int time = atoi(argv[1]);
    int captcha = atoi(argv[2]);
    int cancary = 0;
    int nums[8];
    int i; 
    srand(time);
    for(i=0;i<=7;i++)
    {
        nums[i] = rand();
    }
    cancary = captcha - nums[1] - nums[5] - nums[2] + nums[3] - nums[7] - nums[4] + nums[6] ;
    printf("%x",cancary);
}
