import primefac
import random
from os import urandom
class Unbuffered(object):
   def __init__(self, stream):
       self.stream = stream
   def write(self, data):
       self.stream.write(data)
       self.stream.flush()
   def __getattr__(self, attr):
       return getattr(self.stream, attr)
import sys
from Crypto.Cipher import AES
def aes_cbc_encode(password,iv,m):
    cipher = AES.new(password, AES.MODE_CBC, iv)
    return cipher.encrypt(m)
def aes_cbc_decode(password,iv,c):
    cipher = AES.new(password, AES.MODE_CBC, iv)
    return cipher.decrypt(c)
sys.stdout = Unbuffered(sys.stdout)
def genprime(l):
    l /= 8
    big = 1
    while l:
        big = big << 8
        l -= 1
    big -= 1
    small = (big + 1) >> 4
    temp = random.randint(small, big)
    return primefac.nextprime(temp)
def rsa_gen():
    p = genprime(1024)
    q = genprime(1024)
    n = p * q
    e = 65537
    d = primefac.modinv(e,(p-1)*(q-1)) % ((p-1)*(q-1))
    return (p,q,n,e,d)
def num2str(num):
    h=hex(num)[2:].replace("L","")
    if len(h)%2 ==0 :
        return h.decode("hex")
    else:
        return ("0"+h).decode("hex")
def str2num(str):
    return int(str.encode("hex"),16)
def pad16(str):
    addl=16-(len(str)%16)
    return "a"*addl+str

def run():
    print "====welcome to cry system===="
    (p,q,n,e,d)=rsa_gen()
    print "give you the public key:"
    print "n:"+hex(n).replace("L","")
    print "e:"+hex(e).replace("L","")
    try:
        c=int(raw_input("give me the crypted message in hex:")[2:].strip(),16)
        m=pow(c,d,n)
    except:
        print "wrong input"
    print "your message is",num2str(m)

    flag=open("pathtoflag","r").read().strip()
    aes_key=urandom(16)
    iv=urandom(16)
    cf=aes_cbc_encode(aes_key,iv,pad16(flag))
    ck=pow(str2num(aes_key),e,n)
    civ = pow(str2num(iv), e, n)
    print "encrypted flag:"+cf.encode("base64")+'#'+hex(ck).replace("L","")+'#'+hex(civ).replace("L","")+'#'+hex(p).replace("L","")[2:182]+"##"
run()
