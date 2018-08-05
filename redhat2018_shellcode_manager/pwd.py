#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from z3 import *

s = Solver()
pwd = [BitVec(str(i), 16) for i in xrange(8)]
for i in pwd:
    s.add(And(i > 0, i < 256))
    

s.add(331 * pwd[6] + 317 * pwd[5] + 313 * pwd[4] + 311 * pwd[3] + 307 * pwd[2] + 293 * pwd[1] + 283 * pwd[0] + 337 * pwd[7] == 225643)
s.add(509 * pwd[6] + 503 * pwd[5] + 499 * pwd[4] + 491 * pwd[3] + 487 * pwd[2] + 479 * pwd[1] + 467 * pwd[0] + 521 * pwd[7] == 356507)
s.add(587 * pwd[6] + 577 * pwd[5] + 571 * pwd[4] + 569 * pwd[3] + 563 * pwd[2] + 557 * pwd[1] + 547 * pwd[0] + 593 * pwd[7] == 410769)
s.add(643 * pwd[6] + 641 * pwd[5] + 631 * pwd[4] + 619 * pwd[3] + 617 * pwd[2] + 613 * pwd[1] + 607 * pwd[0] + 647 * pwd[7] == 450797)
s.add(773 * pwd[6] + 769 * pwd[5] + 761 * pwd[4] + 757 * pwd[3] + 751 * pwd[2] + 743 * pwd[1] + 739 * pwd[0] + 787 * pwd[7] == 546531)
s.add(853 * pwd[6] + 839 * pwd[5] + 829 * pwd[4] + 827 * pwd[3] + 823 * pwd[2] + 821 * pwd[1] + 811 * pwd[0] + 857 * pwd[7] == 598393)
s.add(919 * pwd[6] + 911 * pwd[5] + 907 * pwd[4] + 887 * pwd[3] + 883 * pwd[2] + 881 * pwd[1] + 877 * pwd[0] + 929 * pwd[7] == 646297)
s.add(1319 * pwd[6] + 1307 * pwd[5] + 1303 * pwd[4] + 1301 * pwd[3] + 1297 * pwd[2] + 1291 * pwd[1] + 1289 * pwd[0] + 1321 * pwd[7] == 935881)

assert s.check() == sat
print s.model()

flag = ""
for i in xrange(8):
    flag += chr(s.model()[pwd[i]].as_long() & 0xff)

print flag

