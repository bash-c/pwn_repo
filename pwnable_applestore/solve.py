#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from z3 import *

ip6 = Int('ip6')
ip6p = Int('ip6p')
ia2 = Int('ia2')
im3 = Int('im3')
it = Int('it')

print solve(ip6 >= 0, ip6p >= 0, ia2 >= 0, im3 >= 0, it >= 0,ip6 * 199 + ip6p * 299 + ia2 * 499 + im3 * 499 + it * 199 == 7174)
#  s = Solver()
#  s.add(ip6 >= 0, ip6p >= 0, ia2 >=0, im3 >=0, it >= 0)
#  s.add(ip6 * 199 + ip6p * 299 + ia2 * 499 + im3 * 499 + it * 199 == 7174)

#  assert s.check() == sat

#  print s.model()
