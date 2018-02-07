# fastbin中的UAF

> 原文链接：

> 一直对堆漏洞的理解不够，这次借inndy.hackme上的一道基础uaf题目来记录一下fastbin中的uaf漏洞利用

## 预备知识

ptmalloc2的基本知识，如chunk，bin，fastbin，prev_size，size等，重点是如下两张图：

![](http://ww1.sinaimg.cn/large/006AWYXBly1fo71fdre7zj30qz0gc412.jpg)

![](http://ww1.sinaimg.cn/large/006AWYXBly1fo71fyzeebj30tu0gdwhr.jpg)

有几点需要注意：

1. prev_size块在前一chunk不为空时，是前一chunk的user data区
2. malloc返回的是user data开始的地址，32位下，也即是chunk的起始地址+8(prev_size, size)
3. chunk的实际地址=malloc的参数+8（32位下）

## 什么是UAF

![](http://ww1.sinaimg.cn/large/006AWYXBly1fo71o91bwnj30ux0fu0vq.jpg)

也就是说，当free一个指针，但并没有将其置为null时，就可以通过修改这个指针的指向来搞事情了。

在fastbin中，free的chunk并不会与其他的空闲块合并也不会很快将其还给系统内核，系统希望供下一次申请内存的操作使用，写一个demo很容易就能发现。

```C
inndy_raas [master●●] cat demo.c 
/* gcc demo.c -o demo */
#include <stdio.h>
#include <stdlib.h>

int main()
{
	char *p1 = (char *)malloc(0x10);
	printf("p1 -> %p\n", p1);
	free(p1);
	char *p2 = (char *)malloc(0x10);
	printf("p2 -> %p\n", p2);

	return 0;
}
inndy_raas [master●●] ./demo 
p1 -> 0x560f75097010
p2 -> 0x560f75097010
inndy_raas [master●●] 
```

具体怎么用呢？以inndy的raas这道题目展开分析

## inndy_raas

这个题为了照顾新手给了源码

```C
inndy_raas [master●●] cat raas.c 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct record {
	void (*print)(struct record *);
	void (*free)(struct record *);
	union {
		int integer;
		char *string;
	};
};

struct record *records[16];

int ask(const char * q)
{
	char buff[32];
	printf("%s > ", q);
	fgets(buff, sizeof(buff), stdin);
	return atoi(buff);
}

void rec_int_print(struct record *rec)
{
	printf("Record(Type=Integer, Value=%d)\n", rec->integer);
}

void rec_str_print(struct record *rec)
{
	printf("Record(Type=String, Value=%s)\n", rec->string);
}

void rec_int_free(struct record *rec)
{
	free(rec);
	puts("Record freed!");
}

void rec_str_free(struct record *rec)
{
	free(rec->string);
	free(rec);
	puts("Record freed!");
}

void do_new()
{
	int idx = ask("Index");

	if(idx < 0 || idx > 16) {
		puts("Out of index!");
		return;
	}
	if(records[idx]) {
		printf("Index #%d is used!\n", idx);
		return;
	}

	struct record *r = records[idx] = (struct record *)malloc(sizeof(struct record));
	r->print = rec_int_print;
	r->free = rec_int_free;

	puts("Blob type:");
	puts("1. Integer");
	puts("2. Text");
	int type = ask("Type");
	unsigned int len;

	switch(type) {
		case 1:
			r->integer = ask("Value");
			break;
		case 2:
			len = ask("Length");
			if(len > 1024) {
				puts("Length too long, please buy record service premium to store longer record!");
				return;
			}
			r->string = malloc(len);
			printf("Value > ");
			fgets(r->string, len, stdin);
			r->print = rec_str_print;
			r->free = rec_str_free;
			break;
		default:
			puts("Invalid type!");
			return;
	}

	puts("Okey, we got your data. Here is it:");
	r->print(r);
}

void do_del()
{
	int idx = ask("Index");
	records[idx]->free(records[idx]);
}

void do_dump()
{
	int idx = ask("Index");
	records[idx]->print(records[idx]);
}

int main()
{
	alarm(600);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);

	puts("Welcome to use my Record-as-a-Service (free plan)");
	puts("You can only save Integer or String for 600 seconds");
	puts("Pay 1,000,000,000,000,000,000,000,000 bitcoins to buy premium plan");

	puts("Here is term of service. You must agree to use this service. Please read carefully!");
	puts("================================================================================");
	system("cat tos.txt | head -n 30 | sed -e 's/^/    /'");
	puts("================================================================================");


	while(1) {
		puts("1. New record");
		puts("2. Del record");
		puts("3. Show record");

		switch(ask("Act")) {
			case 1:
				do_new();
				break;
			case 2:
				do_del();
				break;
			case 3:
				do_dump();
				break;
			default:
				puts("Bye~ Thanks for using our service!");
				return 0;
		}
	}
}
inndy_raas [master●●] 
```

分析代码，有如下信息：

1. record的chunk如下：

   ![](http://ww1.sinaimg.cn/large/006AWYXBly1fo72rfpk55j30fp04e3yf.jpg)

2. 结构体中存在两个函数指针，应该就是通过这两个函数指针pwn了

3. 仅在do_new选择字符串时才能输入字符串，因此payload应该就是从这里输入了



