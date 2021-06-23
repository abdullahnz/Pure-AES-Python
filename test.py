#!/usr/bin/python3

from aes import *

IV  = b'0123456789abcdef'
KEY = b'thats_the_secret'
MSG = b'Kapan lagi belajar AES'

aes_obj = AES(KEY, IV)
CBC  = aes_obj.encrypt(MSG, AES.MODE_CBC)
PCBC = aes_obj.encrypt(MSG, AES.MODE_PCBC)
ECB  = aes_obj.encrypt(MSG, AES.MODE_ECB)
OFB  = aes_obj.encrypt(MSG, AES.MODE_OFB)
CFB  = aes_obj.encrypt(MSG, AES.MODE_CFB)

print(f'CBC: {CBC.hex()}')
print(f'DEC: {aes_obj.decrypt(CBC, AES.MODE_CBC)}')

print(f'PCBC: {PCBC.hex()}')
print(f'DEC: {aes_obj.decrypt(PCBC, AES.MODE_PCBC)}')

print(f'ECB: {ECB.hex()}')
print(f'DEC: {aes_obj.decrypt(ECB, AES.MODE_ECB)}')

print(f'OFB: {OFB.hex()}')
print(f'DEC: {aes_obj.decrypt(OFB, AES.MODE_OFB)}')

print(f'CFB: {CFB.hex()}')
print(f'DEC: {aes_obj.decrypt(CFB, AES.MODE_CFB)}')

