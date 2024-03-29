#!/usr.bin/python3

REFERENCE = [
    'http://www.infosecwriters.com/text_resources/pdf/AESbyExample.pdf',
    'https://repository.dinus.ac.id/docs/ajar/Advanced_Encryption_Standard_(AES).pdf',
    'https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf',
]

SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

RCON = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
]

SHIFT_LEFT  = [1, 2, 3, 0]
SHIFT_RIGHT = [3, 0, 1, 2]

MULT_MATRIX = [
    2, 3, 1, 1,
    1, 2, 3, 1,
    1, 1, 2, 3,
    3, 1, 1, 2,
]

MULT_MATRIX_INVERS = [
    14, 11, 13,  9,
    9 , 14, 11, 13,
    13,  9, 14, 11,
    11, 13,  9, 14,
]

# 10 rounds for 128-bit keys. (16)
# 12 rounds for 192-bit keys. (24)
# 14 rounds for 256-bit keys. (32)

BIT_KEYS = {
    16 : 10,
    24 : 12,
    32 : 14,
}

class AES:
    MODE_CBC  = 1
    MODE_ECB  = 2
    MODE_PCBC = 3
    MODE_OFB  = 4
    MODE_CFB  = 5

    def __init__(self, key=None, iv=None):
        self.key        = key
        self.initVector = iv

    def pad(self, msg):
        byte = 16 - len(msg) % 16
        return msg + (bytes([byte]) * byte)

    def unpad(self, msg):
        return msg[:-msg[-1]]

    def SBoxSubs(self, msg):
        r = b''
        for key in msg:
            r += bytes([SBOX[key]])
        return r

    def SBOXInvers(self, msg):
        r = b''
        for val in msg:
            r += bytes([SBOX.index(val)])
        return r

    def shiftArr(self, states, shiftTo):
        newArr = b''
        for s in shiftTo:
            newArr += bytes([states[s]])
        return newArr

    def shiftArr_N(self, states, N, shiftTo):
        for _ in range(N):
            states = self.shiftArr(states, shiftTo)
        return states

    def shiftRow(self, states, shifTo):
        result = [0] * 16
        
        for i in range(4):
            tmpArray = []
            
            for j in range(4):
                tmpArray.append(states[i+(4*j)])
            
            tmpArray = self.shiftArr_N(tmpArray, i, shifTo)

            for j in range(4):
                result[i+(4*j)] = tmpArray[j] 
        
        return bytes(result)
        

    def xor(self, x, y):
        r = b''
        for a, b in zip(x, y):
            r += bytes([a ^ b])
        return r

    def keyExpansion(self, key, rconIdx):
        k = [key[i:i+4] for i in range(0, len(key), 4)]
        
        w = self.shiftArr(k[-1], SHIFT_LEFT)
        w = self.SBoxSubs(w)
        w = self.xor(w, [RCON[rconIdx], 0, 0, 0])
        w = self.xor(w, k[-4])

        r = b''
        
        for i in range(4):
            r += w
            k.append(w)
            w = self.xor(k[-1], k[-4])
        
        return r

    def keyExpansionGenerate(self, key):
        key = [key]

        while len(key) <= BIT_KEYS[len(key[0])]:
            key += [self.keyExpansion(key[-1], len(key))]
        
        return key

    # Galois Multiplication | totally copy, lol.
    def galoisMult(self, a, b):
        p = 0
        hiBitSet = 0
        for i in range(8):
            if b & 1 == 1:
                p ^= a
            hiBitSet = a & 0x80
            a <<= 1
            if hiBitSet == 0x80:
                a ^= 0x1b
            b >>= 1
        return p % 256

    # per 4 bytes
    def mixColumnPerBlock(self, states, block, matrix):
        r = b''
        for i in range(4):
            x = 0
            for j in range(4):
                x ^= self.galoisMult(states[j + (4 * block)], matrix[(4 * i) + j])
            r += bytes([x])
        return r

    def mixColumns(self, states):
        r = b''
        for i in range(len(states)//4):
            r += self.mixColumnPerBlock(states, i, MULT_MATRIX)
        return r

    def inverseMixColumns(self, states):
        r = b''
        for i in range(len(states)//4):
            r += self.mixColumnPerBlock(states, i, MULT_MATRIX_INVERS)
        return r

    def addRoundKey(self, states, key):
        return self.xor(states[:16], key[:16])
        
    def pecahPerBlock(self, string, block_size):
        return [string[b:b+block_size] for b in range(0, len(string), block_size)]

    def Encryption(self, plainText, key):
        round_key = len(key)
        key = self.keyExpansionGenerate(key)

        s = self.addRoundKey(plainText, key[0])
        
        for i in range(1, BIT_KEYS[round_key]):
            s = self.SBoxSubs(s)
            s = self.shiftRow(s, SHIFT_LEFT)
            s = self.mixColumns(s)
            s = self.addRoundKey(s, key[i])
        
        s = self.SBoxSubs(s)
        s = self.shiftRow(s, SHIFT_LEFT)
        s = self.addRoundKey(s, key[BIT_KEYS[round_key]])
        
        return s

    def Decryption(self, cipherText, key):
        round_key = len(key)

        key = self.keyExpansionGenerate(key)
        
        s = self.addRoundKey(cipherText, key[BIT_KEYS[round_key]])
        s = self.shiftRow(s, SHIFT_RIGHT)
        s = self.SBOXInvers(s)

        for i in range(BIT_KEYS[round_key]-1, 0, -1):
            s = self.addRoundKey(s, key[i])
            s = self.inverseMixColumns(s)
            s = self.shiftRow(s, SHIFT_RIGHT)
            s = self.SBOXInvers(s)
        
        s = self.addRoundKey(s, key[0])
        return s

    def CBC(self, plainText):
        plainText = self.pad(plainText)
        plainText = self.pecahPerBlock(plainText, 16)
        r = b''
        for i in range(len(plainText)):
            keyStream  = self.xor(plainText[i], self.initVector)
            self.initVector = self.Encryption(keyStream, self.key)
            r += self.initVector
        return r
    
    def ECB(self, plainText):
        plainText = self.pad(plainText)
        plainText = self.pecahPerBlock(plainText, 16)
        r = b''
        for i in range(len(plainText)):
            r += self.Encryption(plainText[i], self.key)
        return r
    
    def PCBC(self, plainText):
        plainText = self.pad(plainText)
        plainText = self.pecahPerBlock(plainText, 16)

        r = b''
        for i in range(len(plainText)):
            s = self.xor(plainText[i], self.initVector)   
            s = self.Encryption(s, self.key)
            self.initVector = self.xor(plainText[i], s)
            r += s
        return r
    
    def CFB(self, plainText):
        plainText = self.pad(plainText)
        plainText = self.pecahPerBlock(plainText, 16)

        r = b''
        for i in range(len(plainText)):
            keyStream = self.Encryption(self.initVector, self.key)
            self.initVector = self.xor(keyStream, plainText[i])
            r += self.initVector
        
        return r

    def OFB(self, plainText):
        plainText = self.pad(plainText)
        plainText = self.pecahPerBlock(plainText, 16)
        
        r = b''
        for i in range(len(plainText)):
            keyStream = self.Encryption(self.initVector, self.key)
            r += self.xor(plainText[i], keyStream)
            self.initVector = keyStream
        return r

    def encrypt(self, plainText, mode):
        oldInitVector = self.initVector
        oldSecretKey  = self.key

        ciphertext = b''
        if mode == self.MODE_CBC:
            ciphertext = self.CBC(plainText)
        elif mode == self.MODE_ECB:
            ciphertext = self.ECB(plainText)
        elif mode == self.MODE_PCBC:
            ciphertext = self.PCBC(plainText)
        elif mode == self.MODE_OFB:
            ciphertext = self.OFB(plainText)
        elif mode == self.MODE_CFB:
            ciphertext = self.CFB(plainText)
        
        self.initVector = oldInitVector
        self.key        = oldSecretKey

        return ciphertext

    def InverseECB(self, cipherText):
        cipherText = self.pecahPerBlock(cipherText, 16)
        
        p = b''
        for i in range(len(cipherText)):
            p += self.Decryption(cipherText[i], self.key)
        return self.unpad(p)

    def InverseCFB(self, cipherText):
        cipherText = self.pecahPerBlock(cipherText, 16)

        p = b''
        for i in range(len(cipherText)):
            keyStream = self.Encryption(self.initVector, self.key)
            p += self.xor(cipherText[i], keyStream)
            self.initVector = cipherText[i]
        
        return self.unpad(p)

    def InverseCBC(self, cipherText):
        cipherText = self.pecahPerBlock(cipherText, 16)
        
        p = b''
        for i in range(len(cipherText)):
            keyStream = self.Decryption(cipherText[i], self.key)
            p += self.xor(self.initVector, keyStream)
            self.initVector = cipherText[i]
        return self.unpad(p)

    def InversePCBC(self, cipherText):
        cipherText = self.pecahPerBlock(cipherText, 16)

        p = b''
        for i in range(len(cipherText)):
            keyStream = self.Decryption(cipherText[i], self.key)
            s = self.xor(keyStream, self.initVector)
            self.initVector = self.xor(cipherText[i], s)
            p += s
        return self.unpad(p)

    def InverseOFB(self, cipherText):
        cipherText = self.pecahPerBlock(cipherText, 16)

        p = b''
        for i in range(len(cipherText)):
            keyStream = self.Encryption(self.initVector, self.key)
            p += self.xor(cipherText[i], keyStream)
            self.initVector = keyStream

        return self.unpad(p)

    def decrypt(self, cipherText, mode):
        oldInitVector = self.initVector
        oldSecretKey  = self.key

        plaintext = b''
        if mode == self.MODE_CBC:
            plaintext = self.InverseCBC(cipherText)
        elif mode == self.MODE_ECB:
            plaintext = self.InverseECB(cipherText)
        elif mode == self.MODE_PCBC:
            plaintext = self.InversePCBC(cipherText)
        elif mode == self.MODE_OFB:
            plaintext = self.InverseOFB(cipherText)
        elif mode == self.MODE_CFB:
            plaintext = self.InverseCFB(cipherText)

        self.initVector = oldInitVector
        self.key        = oldSecretKey

        return plaintext
