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

###保护机制

```bash
pwnable_hacknote [master●●] cat ~/pwndbg/check.sh 
#!/usr/bin/env bash

checksec $1
file $1
pwnable_hacknote [master●●] check hacknote 
[*] '/home/m4x/pwn_repo/pwnable_hacknote/hacknote'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
hacknote: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a32de99816727a2ffa1fe5f4a324238b2d59a606, stripped
```

32位动态链接的程序，开启了栈溢出保护和NX，在栈的利用上就造成了困难

###程序流程

通过运行程序结合IDA分析程序流程，很容易得出程序有**添加，删除，打印note**三个功能，其中添加最多添加5个note，note的数据结构如下：

```C
struct NODE
{
	void (*print)(struct NODE *);
	char *content;
}
```

> 这里简单介绍一下如何在IDA中恢复结构体，我习惯使用添加local types的方法。
>
> - 识别出结构体的形式后，IDA中使用快捷键shift + F1切换到Local Types界面，insert键插入，输入结构体定义，点击OK添加，如下图：
>
>   ![](http://ww1.sinaimg.cn/large/006AWYXBly1fogrv1b56wj30lv07ijs0.jpg)
>
> - shift + F9，切换到Structures界面，insert键插入，点击Add standerd structure，在弹出的窗口中拖到最下边找到我们插入的结构体，选中点击OK，如下图：
>
>   ![](http://ww1.sinaimg.cn/large/006AWYXBly1fogry9gkcaj30nb09omyc.jpg)
>
> - 切换到结构体所在的位置，y设置变量类型，如下图：
>
>   ![](http://ww1.sinaimg.cn/large/006AWYXBly1fogs0y3zrej30ew09jjrl.jpg)
>
> - 伪代码页重新F5，就能看到修复好结构体的高度还原的伪代码了，下边是修复前后的对比图
>
>   ![](http://ww1.sinaimg.cn/large/006AWYXBly1fogs1y3vsaj30d5087dga.jpg)
>
>   ![](http://ww1.sinaimg.cn/large/006AWYXBly1fogs2eyuqkj30jl086t9g.jpg)

这样每个note在内存中的布局如下：

![](http://ww1.sinaimg.cn/large/006AWYXBly1fogsgo59jwj30q80bjq38.jpg)

note_chunk中的prev_size和size为chunk的meta data，记录了chunk的一些信息，\*print和\*content为两个指针，存储了两个地址，不同的是，\*print为一个函数指针，指向了一个函数，\*content存储了另一个chunk的地址，该chunk存储了用户输入的note content。

### 利用思路：

####程序漏洞：

很容易发现程序的漏洞

![](http://ww1.sinaimg.cn/large/006AWYXBly1fogtd0qe0jj30l807ut9n.jpg)

用户输入note content的size是由自己指定的，那么如果我们能控制\*content的指向，就能覆写其他chunk的prev_size, size等meta data甚至是\*print等函数指针。

#### uaf

那么如何控制*content指向呢？这里就要用到uaf了，思路如下：

1. 先申请两个size为24的note(考虑到对齐，size在fastbin范围内，只要不是1 * 8即可，原因之后解释)
2. free两个note
3. 再申请一个size为8的note，根据first-fit原则，该note_chunk的*content即会指向我们第一个free的note_chunk

