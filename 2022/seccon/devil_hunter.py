'''
Extract IR Logic -> `clambc --printbcir` options
'''
key = [0x739e80a2, 0x3aae80a3, 0x3ba4e79f, 0x78bac1f3, 0x5ef9c1f3, 0x3bb9ec9f, 0x558683f4, 0x55fad594, 0x6cbfdd9f]

answer = 0xacab3c0

def F2(arg):
        local_key = 0xacab3c0
        for i in range(4):
                v10 = ((arg >> (i * 8)) & 0xff) ^ local_key
                local_key = (((v10 << 8) & 0xffffffff) | (local_key >> 0x18))

        return local_key


def inverse_F2(arg):
        answer = []
        backup = [0xb3, 0xca, 0x0a, 0xc0]

        key = arg
        for i in range(4):
                v10 = key >> 8
                v10 |= (key & 0xff) << 24
                key = v10 & 0xffffff00
                key |= backup[i]

                answer.append(key ^ v10)

        return answer[::-1]

msg = ''
for i in key:
        msg += ''.join(chr(_) for _ in inverse_F2(i))

print(msg)
