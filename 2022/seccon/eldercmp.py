def BYTE(x, n):
    return (x >> (8 * n)) & 0xff

def LSH(x, n):
    return x << (8 * n)


def RSH(x, n):
    return x >> (8 * n)

rbp = [
    0x50, 0x94, 0x2F, 0x28, 0x49, 0x56, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x73, 0x6E, 0x6F, 0x66, 0x2F, 0x2F, 0x2F,
    0x00, 0x42, 0x6E, 0x73, 0x73, 0x64, 0x62, 0x75, 0x20, 0x00, 0x0C, 0x00, 0x0F, 0x0A, 0x02, 0x0B,
    0x09, 0x05, 0x08, 0x03, 0x0D, 0x07, 0x01, 0x0E, 0x06, 0x04, 0x11, 0x45, 0x14, 0x19, 0x19, 0x81,
    0x09, 0x31, 0x88, 0x94, 0x64, 0x51, 0x28, 0x10, 0x93, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x03, 0x06, 0x0C, 0x18, 0x30, 0x23, 0x05, 0x0A, 0x14, 0x28, 0x13, 0x26, 0x0F, 0x1E, 0x3C, 0x3B,
    0x35, 0x29, 0x11, 0x22, 0x07, 0x0E, 0x1C, 0x38, 0x33, 0x25, 0x09, 0x12, 0x24, 0x0B, 0x05, 0x09,
    0x09, 0x08, 0x01, 0x00, 0x05, 0x04, 0x01, 0x01, 0x05, 0x04, 0x04, 0x08, 0x08, 0x01, 0x09, 0x0F,
    0x01, 0x08, 0x01, 0x06, 0x03, 0x08, 0x08, 0x01, 0x01, 0x03, 0x03, 0x02, 0x05, 0x03, 0x0F, 0x03,
    0x05, 0x04, 0x0C, 0x09, 0x04, 0x09, 0x0B, 0x03, 0x08, 0x01, 0x07, 0x01, 0x01, 0x05, 0x06, 0x06,
    0x03, 0x08, 0x0A, 0x0F, 0x03, 0x01, 0x06, 0x08, 0x05, 0x03, 0x01, 0x01, 0x0F, 0x01, 0x09, 0x09,
    0x04, 0x09, 0x06, 0x03, 0x01, 0x05, 0x0B, 0x00, 0x01, 0x05, 0x09, 0x03, 0x0E, 0x08, 0x05, 0x01,
    0x03, 0x01, 0x02, 0x06, 0x01, 0x03, 0x08, 0x0E, 0x0F, 0x01, 0x0B, 0x08, 0x06, 0x05, 0x0B, 0x03,
    0x01, 0x05, 0x05, 0x09, 0x0A, 0x04, 0x00, 0x00, 0x0E, 0x08, 0x0C, 0x00, 0x07, 0x01, 0x0A, 0x08,
    0x01, 0x03, 0x08, 0x01, 0x09, 0x03, 0x08, 0x04, 0x06, 0x05, 0x07, 0x0E, 0x01, 0x0F, 0x0F, 0x02,
    0x0A, 0x04, 0x06, 0x03, 0x0C, 0x01, 0x0A, 0x05, 0x07, 0x01, 0x06, 0x00, 0x0B, 0x0E, 0x0D, 0x09,
    0x09, 0x03, 0x03, 0x08, 0x01, 0x01, 0x06, 0x04, 0x01, 0x0F, 0x07, 0x04, 0x01, 0x06, 0x01, 0x05,
    0x0C, 0x01, 0x05, 0x02, 0x00, 0x0A, 0x0F, 0x04, 0x0B, 0x0E, 0x0D, 0x05, 0x07, 0x07, 0x03, 0x0D,
    0x01, 0x01, 0x0E, 0x09, 0x04, 0x09, 0x07, 0x06, 0x01, 0x06, 0x0A, 0x04, 0x00, 0x01, 0x00, 0x0D,
    0x00, 0x0A, 0x01, 0x05, 0x0C, 0x0C, 0x0E, 0x0D, 0x07, 0x07, 0x01, 0x04, 0x0F, 0x0B, 0x0B, 0x0F,
    0x04, 0x09, 0x01, 0x0D, 0x08, 0x01, 0x0A, 0x05, 0x00, 0x01, 0x00, 0x06, 0x06, 0x01, 0x0C, 0x0E,
    0x0C, 0x0C, 0x0C, 0x0D, 0x07, 0x00, 0x0A, 0x03, 0x0F, 0x0B, 0x0C, 0x0D, 0x05, 0x07, 0x03, 0x02,
    0x08, 0x01, 0x01, 0x0F, 0x00, 0x04, 0x02, 0x02, 0x06, 0x01, 0x06, 0x05, 0x0F, 0x00, 0x06, 0x0D,
    0x07, 0x00, 0x07, 0x0E, 0x09, 0x0C, 0x0B, 0x08, 0x05, 0x07, 0x02, 0x03, 0x00, 0x0F, 0x05, 0x08,
    0x00, 0x04, 0x06, 0x02, 0x04, 0x08, 0x03, 0x06, 0x0D, 0x02, 0x0F, 0x00, 0x0A, 0x0D, 0x00, 0x00
]

def reverse(msg):
    msg = msg[::-1]
    output = ''
    for i in range(len(msg)):
        if i % 2 == 0:
            output += msg[i+1]
            output += msg[i]
    return output


def decrypt(enc):
    enc = enc.rjust(0x10, '0')
    low = ""
    for i in range(0, 8, 2):
        low += "0{}0{}".format(enc[i+1], enc[i])

    high = ""
    for i in range(8, 16, 2):
        high += "0{}0{}".format(enc[i+1], enc[i])
    high = int(high, 16)
    low = int(low, 16)

    high ^= LSH(rbp[BYTE(BYTE(high, 0) ^ rbp[0x196], 0) + 0x2a], 1)
    high ^= LSH(rbp[BYTE(BYTE(high, 2) ^ rbp[0x197], 0) + 0x2a], 3)
    high ^= LSH(rbp[BYTE(BYTE(high, 4) ^ rbp[0x198], 0) + 0x2a], 5)
    high ^= LSH(rbp[BYTE(BYTE(high, 6) ^ rbp[0x199], 0) + 0x2a], 7)

    low ^= LSH(rbp[BYTE(BYTE(low, 0) ^ rbp[0x19a], 0) + 0x2a], 1)
    low ^= LSH(rbp[BYTE(BYTE(low, 2) ^ rbp[0x19b], 0) + 0x2a], 3)
    low ^= LSH(rbp[BYTE(BYTE(low, 4) ^ rbp[0x19c], 0) + 0x2a], 5)
    low ^= LSH(rbp[BYTE(BYTE(low, 6) ^ rbp[0x19d], 0) + 0x2a], 7)

    prev_low = low
    prev_high = high

    for i in range(0x196 - 8, 0x7e - 8, -8):
        new_high = 0
        new_low  = 0

        new_high |= ((prev_low >> 8*0) & 0xff) << 7*8
        new_low  |= ((prev_low >> 8*1) & 0xff) << 2*8
        new_low  |= ((prev_low >> 8*2) & 0xff) << 5*8
        new_low  |= ((prev_low >> 8*3) & 0xff) << 6*8
        new_high |= ((prev_low >> 8*4) & 0xff) << 5*8
        new_low  |= ((prev_low >> 8*5) & 0xff) << 0*8
        new_low  |= ((prev_low >> 8*6) & 0xff) << 7*8
        new_low  |= ((prev_low >> 8*7) & 0xff) << 4*8


        new_high |= ((prev_high >> 8*0) & 0xff) << 1*8
        new_high |= ((prev_high >> 8*1) & 0xff) << 2*8
        new_low  |= ((prev_high >> 8*2) & 0xff) << 3*8
        new_high |= ((prev_high >> 8*3) & 0xff) << 6*8
        new_high |= ((prev_high >> 8*4) & 0xff) << 3*8
        new_high |= ((prev_high >> 8*5) & 0xff) << 0*8
        new_low  |= ((prev_high >> 8*6) & 0xff) << 1*8
        new_high |= ((prev_high >> 8*7) & 0xff) << 4*8

        prev_high = new_high
        prev_low = new_low

        prev_high ^= LSH(rbp[BYTE(BYTE(prev_high, 0) ^ rbp[i], 0) + 0x2a], 1)
        prev_high ^= LSH(rbp[BYTE(BYTE(prev_high, 2) ^ rbp[i + 1], 0) + 0x2a], 3)
        prev_high ^= LSH(rbp[BYTE(BYTE(prev_high, 4) ^ rbp[i + 2], 0) + 0x2a], 5)
        prev_high ^= LSH(rbp[BYTE(BYTE(prev_high, 6) ^ rbp[i + 3], 0) + 0x2a], 7)

        prev_low ^= LSH(rbp[BYTE(BYTE(prev_low, 0) ^ rbp[i + 4], 0) + 0x2a], 1)
        prev_low ^= LSH(rbp[BYTE(BYTE(prev_low, 2) ^ rbp[i + 5], 0) + 0x2a], 3)
        prev_low ^= LSH(rbp[BYTE(BYTE(prev_low, 4) ^ rbp[i + 6], 0) + 0x2a], 5)
        prev_low ^= LSH(rbp[BYTE(BYTE(prev_low, 6) ^ rbp[i + 7], 0) + 0x2a], 7)

    high = "{:016x}".format(prev_high)
    low = "{:016x}".format(prev_low)

    flag1 = ''
    flag2 = ''
    for i in range(0, len(high), 4):
        flag1 += chr(int(high[i+3] + high[i+1], 16))

    for i in range(0, len(low), 4):
        flag2 += chr(int(low[i+3] + low[i+1], 16))

    return flag1[::-1] + flag2[::-1]

answer = ["5894A5AF7F7693B7", "94706B86CE8E1CCE", "98BA6F1FF3CC98", "0AE6575961AF354C", "D853F981DF45AB41", 'E1FEFD554E662F7F', '3CA11FB09E498AB4']

for enc in answer:
    print(decrypt(enc), end='')
