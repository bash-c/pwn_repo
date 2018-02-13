# fastbin中的UAF

> 原文链接：

> 一直对堆漏洞的理解不够，这次借pwnable.tw上的一道基础uaf题目来记录一下fastbin中的uaf漏洞利用

## 预备知识

ptmalloc2的基本知识，如chunk，bin，fastbin，prev_size，size等，重点是下图：

![](http://ww1.sinaimg.cn/large/006AWYXBly1fofbrc8tnvj30xv0bqq42.jpg)

有几点需要注意：

1. prev_size块在前一chunk不为空时，是前一chunk的data区
2. malloc返回的是user data开始的地址，32位下，也即是chunk的起始地址+8(prev_size + size)
3. chunk的实际大小=malloc的参数+8（32位下）

## 什么是UAF

![](http://ww1.sinaimg.cn/large/006AWYXBly1fo71o91bwnj30ux0fu0vq.jpg)

也就是说，当free一个指针，但并没有将其置为null时，就可以通过修改这个指针的指向来搞事情了。

在fastbin中，free的chunk并不会与其他的空闲块合并也不会很快将其还给系统内核，系统希望供下一次申请内存的操作使用，写一个demo很容易就能发现。

```C
pwnable_hacknote [master] cat demo.c 
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
pwnable_hacknote [master] ./demo 
p1 -> 0x55bcd54ea010
p2 -> 0x55bcd54ea010
pwnable_hacknote [master]
```

具体怎么用呢？以pwnable.tw的hacknote这道题目为例展开分析

## pwnable.tw_hacknote

经过分析，程序中存在这样一个结构体：

```C
struct NODE
{
    void (*print)(struct NODE *);
    char *content;
}
```

print为函数指针，content为指向用户输入的指针。

用户有创建5个note，修改note和删除note的能力，

