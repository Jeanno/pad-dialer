import os
from paddingdialer import PaddingDialer
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


def to_hex(byte_ary):
    return ''.join(format(x, '02x') for x in byte_ary)

backend = default_backend()
key = os.urandom(16)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

def pad_and_encrypt(msg):
    padder = padding.PKCS7(128).padder()
    padded = padder.update(msg) + padder.finalize()
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


if __name__ == '__main__':
    msg = b"this is block 1 this is block 2 this is block 3 this is block 4"
    encrypted = pad_and_encrypt(msg)


    class MyDialer(PaddingDialer):
        def check_padding(self, byte_ary):
            # Note that this method only leaks padding validation result.
            # It does not give cipher key, plaintext, or other intermediate
            # decrpytion information.
            # The user can possibly implement this method to send a request to
            # an HTTP API if that API leaks the same padding validation result.
            decryptor = cipher.decryptor()
            p = decryptor.update(byte_ary) + decryptor.finalize()

            try:
                unpadder = padding.PKCS7(128).unpadder()
                data = unpadder.update(p) + unpadder.finalize()
            except:
                return False

            return True


    pd = MyDialer()
    pd.set_encrypted_bytes(encrypted)
    pd.set_block_size_in_byte(16)
    print(pd.start())
