BITS 32
org 0x804ab00
push 0x33
call next
next:
add dword [esp], 5
retf
