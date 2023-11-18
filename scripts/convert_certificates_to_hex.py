import sys, random, base64, os, json
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
import glob

path = os.path.join(os.getcwd(), 'certificates')
for file in glob.glob(os.path.join(path, "*.crt"))+glob.glob(os.path.join(path, "*.key")):
    with open(file, "r") as f:
        content = f.read()
        content = content.replace("\r\n", "\n")
        content = str.encode(content)
        
    # Generate output as hex with 0x00 at the end
    output = ','.join([hex(val) for val in content]) + ',0x00'
    with open(file+".hexarr", "w") as f:
        f.write(output)

print('DONE')