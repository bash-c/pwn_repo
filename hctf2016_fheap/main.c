#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct String{
    union {
        char *buf;
        char array[16];
    } o;
    int len;
    void (*free)(struct String *ptr);
} String;

struct {
    int inuse;
    String *str;
} Strings[0x10];

void showMenu(void);

int getInt(void);

void creatStr();

void deleteStr();

void freeShort(String *str);

void freeLong(String *str);
int getInt(void) {
    char str[11];
    char ch;
    int i;
    for (i = 0; (read(STDIN_FILENO, &ch, 1), ch) != '\n' && i < 10 && ch != -1; i++) {
        str[i] = ch;
    }
    str[i] = 0;
    return atoi(str);
}

int main(void) {
	char buf[1024];
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);

    printf("+++++++++++++++++++++++++++\n");
    printf("So, let's crash the world\n");
    printf("+++++++++++++++++++++++++++\n");


    while (1) {
        showMenu();
		if(read(STDIN_FILENO,buf,1024)==0){
			return 1;
		}
		if(!strncmp(buf,"create ",7)) {
			creatStr();
		} 
		else if (!strncmp(buf,"delete ",7)) {
            deleteStr();
		}
		else if(!strncmp(buf,"quit ",5)) {
            printf("Bye~\n");
            return 0;
		}
		else{
            printf("Invalid cmd\n");
        }
    }

}
void freeShort(String *str) {
    free(str);
}

void freeLong(String *str) {
    free(str->o.buf);
    free(str);
}

void deleteStr() {
    int id;
	char buf[0x100];
    printf("Pls give me the string id you want to delete\nid:");
    id = getInt();
    if (id < 0 || id > 0x10) {
        printf("Invalid id\n");
    }
    if (Strings[id].str) {
		printf("Are you sure?:");
		read(STDIN_FILENO,buf,0x100);
		if(strncmp(buf,"yes",3)) {
			return;
		}
        Strings[id].str->free(Strings[id].str);
        Strings[id].inuse = 0;
    }
}


void creatStr() {
    String *string = malloc(sizeof(String));
    int i;
    char *str = NULL;
    char buf[0x1000];
    size_t size;

    printf("Pls give string size:");
    size = (size_t) getInt();
    if (size < 0 || size > 0x1000) {
        printf("Invalid size\n");
        free(string);
        return;
    }
	printf("str:");
    if (read(STDIN_FILENO, buf, size) == -1) {
        printf("got elf!!\n");
        exit(1);
    }
    size = strlen(buf);
    if (size < 16) {
        strncpy(string->o.array, buf, size);
        string->free = freeShort;
    }
    else {
        str = malloc(size);
        if (str == NULL) {
            printf("malloc faild!\n");
            exit(1);
        }
        strncpy(str, buf, size);
        string->o.buf = str;
        string->free = freeLong;

    }

    string->len = (int) size;
    for (i = 0; i < 0x10; i++) {
        if (Strings[i].inuse == 0) {
            Strings[i].inuse = 1;
            Strings[i].str = string;
            printf("The string id is %d\n", i);
            break;
        }
    }
    if (i == 0x10) {
        printf("The string list is full\n");
        string->free(string);
    }
}


void showMenu(void) {
    printf("1.create string\n");
    printf("2.delete string\n");
    printf("3.quit\n");
}


