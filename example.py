import os
from paddingdialer import PaddingDialer
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding




def test1():
    key = Fernet.generate_key()
    f = Fernet(key)
    token = f.encrypt(b"A really secret message. Not for prying eyes.sssssssss")
    print(token)
    p = f.decrypt(token)
    print(p)

    token2 = f.encrypt(b"1")
    print(token2)
    p = f.decrypt(token2)
    print(p)

    token3 = b'gAAAAABeM51rjz1y1Am3RwFXJgSQMRjSzIT8Ssox-tUPhqX3R7EUQWJbvNazpUsFpWSfsS4eZa5EuQBVpGYBKpii7qPAqKBiCINZEJxQ-_JCFMbCafAQIWjLDh3I3NA0LqcZHk0pUItw69ZPrP1SF5y4z98gyXiu9f=='
    p = f.decrypt(token3)
    print(p)

def to_hex(byte_ary):
    return ''.join(format(x, '02x') for x in byte_ary)

if __name__ == '__main__':
    backend = default_backend()
    key = os.urandom(16)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    padder = padding.PKCS7(128).padder()
    encryptor = cipher.encryptor()
    msg = b"this is block 1 this is block 2 this is block 3 this is block 4"
    padded = padder.update(msg) + padder.finalize()
    #print(padded)
    ct = encryptor.update(padded) + encryptor.finalize()
    #print(to_hex(ct))


    class MyDialer(PaddingDialer):
        def check_padding(self, byte_ary):
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(128).unpadder()
            p = decryptor.update(byte_ary) + decryptor.finalize()
            try:
                data = unpadder.update(p) + unpadder.finalize()
            except:
                return False

            return True



    pd = MyDialer()
    pd.set_encrypted_bytes(ct)
    pd.set_block_size_in_byte(16)
    print(pd.start())
