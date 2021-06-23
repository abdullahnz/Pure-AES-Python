# Advanced Encryption Standard (Rijndael)

Pure AES implemented in python3.

## Usage

You can import this script into your python script. 

```py
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
```

Output

```sh
❯ python3 test.py 
CBC: e3b0204470ff14e4f0d6834b5113abff73d8810bca4fb5c0fcbc499c9439e1d4
DEC: b'Kapan lagi belajar AES'
PCBC: e3b0204470ff14e4f0d6834b5113abff5ecfdd208c550573441a2636d7739bb7
DEC: b'Kapan lagi belajar AES'
ECB: 433e1a18518df1f66bf2e82c50b1c22382b2457db909419d0c00c94ea00e2f42
DEC: b'Kapan lagi belajar AES'
OFB: d2c0275107f125a35d68fb7793abd1d510e369c849fc225f838187c010ef620f
DEC: b'Kapan lagi belajar AES'
CFB: d2c0275107f125a35d68fb7793abd1d594db203982ad790e8d3a82cfdb9bdd18
DEC: b'Kapan lagi belajar AES'
```

## Requirement

- Only python3.x

## Updates

- Now implemented with class.
- Reuseable object.

## References

- https://www.cryptool.org/en/cto/highlights/aes-step-by-step
- http://www.infosecwriters.com/text_resources/pdf/AESbyExample.pdf
- https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf
- https://repository.dinus.ac.id/docs/ajarAdvanced_Encryption_Standard_(AES).pdf
- https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
- etc.
