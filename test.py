#!/usr/bin/python3

from main import *

IV  = b'0123456789abcdef'
KEY = b'thats_the_secret'
MSG = b'Kapan lagi belajar AES'

ecb  = ECB(MSG, KEY)
cfb  = CFB(MSG, KEY, IV)
cbc  = CBC(MSG, KEY, IV)
ofb  = OFB(MSG, KEY, IV)
pcbc = PCBC(MSG, KEY, IV)

print(f'ECB_MODE : {ecb.hex()}')
print(f'DECRYPTED: {InverseECB(ecb, KEY)}\n')

print(f'CFB_MODE : {cfb.hex()}')
print(f'DECRYPTED: {InverseCFB(cfb, KEY, IV)}\n')

print(f'CBC_MODE : {cbc.hex()}')
print(f'DECRYPTED: {InverseCBC(cbc, KEY, IV)}\n')

print(f'OFB_MODE : {ofb.hex()}')
print(f'DECRYPTED: {InverseOFB(ofb, KEY, IV)}\n')

print(f'PCBC_MODE: {pcbc.hex()}')
print(f'DECRYPTED: {InversePCBC(pcbc, KEY, IV)}\n')



