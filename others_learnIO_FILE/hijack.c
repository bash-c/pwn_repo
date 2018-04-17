#include <stdio.h>

int main(void)
{
    FILE *fp;
    long long *vtable_ptr;
    fp=fopen("123.txt","rw");
    vtable_ptr=*(long long*)((long long)fp+0xd8);     //get vtable

    vtable_ptr[7]=0x41414141; //xsputn

    printf("call 0x41414141");
}

