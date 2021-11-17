import sys
import base64

from Crypto.Cipher import AES
from Crypto.Util import Counter

key = sys.argv[1]
iv = sys.argv[2]
filename = sys.argv[3]
with open(filename) as f:
    plaintext = f.read()

ctr = Counter.new(128, initial_value = int.from_bytes(iv.encode('ascii'), byteorder='big'))
algorithm = AES.new(key.encode('ascii'), AES.MODE_CTR, counter=ctr)
ciphertext = base64.b64encode(algorithm.encrypt(plaintext.encode('ascii')))
ciphertext = ciphertext.decode('utf-8')
print(ciphertext)