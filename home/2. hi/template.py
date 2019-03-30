from pwn import *

elf = ELF("./hi")

print "This binary has many symbols:"
print elf.symbols

p = process("./hi")

p.sendline("Andrea")

print p.recvall()

