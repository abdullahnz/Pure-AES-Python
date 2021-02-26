# Advanced Encryption Standard (Rijndael)

Pure AES implemented in python3.

## Usage

You can modify the main file or importing main file to your python script.

```py
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
```

Output

```sh
$ python3 test.py 
ECB_MODE : 433e1a18518df1f66bf2e82c50b1c22382b2457db909419d0c00c94ea00e2f42
DECRYPTED: b'Kapan lagi belajar AES'

CFB_MODE : d2c0275107f125a35d68fb7793abd1d594db203982ad790e8d3a82cfdb9bdd18
DECRYPTED: b'Kapan lagi belajar AES'

CBC_MODE : e3b0204470ff14e4f0d6834b5113abff73d8810bca4fb5c0fcbc499c9439e1d4
DECRYPTED: b'Kapan lagi belajar AES'

OFB_MODE : d2c0275107f125a35d68fb7793abd1d510e369c849fc225f838187c010ef620f
DECRYPTED: b'Kapan lagi belajar AES'

PCBC_MODE: e3b0204470ff14e4f0d6834b5113abff5ecfdd208c550573441a2636d7739bb7
DECRYPTED: b'Kapan lagi belajar AES'
```

## Requirement

- Only python3.x

## Todo, Insyaallah

- Implemented with Class.
- Support all modes.

## References

- https://www.cryptool.org/en/cto/highlights/aes-step-by-step
- http://www.infosecwriters.com/text_resources/pdf/AESbyExample.pdf
- https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf
- https://repository.dinus.ac.id/docs/ajarAdvanced_Encryption_Standard_(AES).pdf
- https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
- etc.
