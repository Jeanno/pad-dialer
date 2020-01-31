import base64

class PaddingDialer:
    def __init__(self):
        self.encrypted_bytes = None
        self.iv = None
        self.block_size_in_byte = int(128 / 8)


    def set_encrypted_bytes(self, encrypted_bytes):
        self.encrypted_bytes = encrypted_bytes


    def set_encrypted_bytes_from_hex(self, encrypted_hex):
        self.set_encrypted_bytes(bytearray.fromhex(encrypted_hex))


    def set_iv(self, iv):
        self.iv = iv


    def set_block_size_in_byte(self, block_size):
        self.block_size_in_byte = block_size


    def get_block(self, num):
        s = self.block_size_in_byte
        return self.encrypted_bytes[s * num: s * (num + 1)]


    def start(self):
        # Let plaintext = p
        # Case #1
        # last byte of p is not 01
        # last 2 bytes of p = 0202, 0303, ...., fefe, ffff
        # Next valid padding ends with 01
        #
        # Case #2
        # last byte of p is 01
        # Case #2a
        # last bytes of p = 0201 or 030301 or 04040401 or .....
        # Next valid is 0202 or 030303 or 04040404 etc.
        #
        # Case #2b
        # last byte of p = 01 where and not in case #2
        # only the original bytes can pass checking
        p = self.solve_block(self.get_block(0), self.get_block(1))
        return p

    def solve_block(self, prev_block, target_block):
        print(to_hex(prev_block))
        print(to_hex(target_block))
        dial_block = bytearray(prev_block)

        for i in reversed(range(self.block_size_in_byte)):
            set_to = self.block_size_in_byte - i
            for j in range(i + 1, self.block_size_in_byte):
                dial_block[j] ^= set_to ^ (set_to - 1)

            count = 0
            while True:
                dial_block[i] = (dial_block[i] + 1) % 256
                if self.check_padding(dial_block + target_block):
                    break

                count += 1
                if count > 256:
                    raise Exception("Cannot dial to right padding")


        plaintext = bytes(d ^ p ^ self.block_size_in_byte for (d, p) in zip(dial_block, prev_block))
        print("Solved")
        print(plaintext)
        return plaintext


    def check_padding(self, byte_ary):
        return True
        #print(to_hex(byte_ary))
        b64_str = base64.b64encode(byte_ary).decode('utf-8')
        b64_str = b64_str.replace('=', '~').replace('+', '-').replace('/', '!')
        #print(b64_str)
        res = requests.get("http://35.227.24.107/9cb724f593/?post=" + b64_str)
        #x = input()
        if "PaddingException" not in res.text:
            print(res.text)
            return True
        else:
            return False


    def cal_num_blocks(self):
        if len(self.encrypted_bytes) % self.block_size_in_byte != 0:
            raise Exception("Last block of encrypted bytes is incomplete")

        return len(self.encrypted_bytes) / self.block_size_in_byte


def to_hex(byte_ary):
    return ''.join(format(x, '02x') for x in byte_ary)


if __name__ == '__main__':
    pd = PaddingDialer()
    pd.set_encrypted_bytes_from_hex('deadbeefdeadbeefdeadbeefdeadbeef')

    print(pd.encrypted_bytes)
    print(pd.encrypted_bytes[0:4])

    assert len(pd.encrypted_bytes) == 16

    pd.set_block_size_in_byte(16)

    assert pd.cal_num_blocks() == 1

    pd.set_encrypted_bytes_from_hex(
            'deadbeefdeadbeefdeadbeefdeadbeef'
            '01234567012345670123456701234567'
    )

    print(to_hex(pd.get_block(0)))
    print(to_hex(pd.get_block(1)))

    pd.set_encrypted_bytes_from_hex(
        '06 e1 ca ad 2f 26 f6 d5 e6 3d 06 11 2e ca 49 d6'
        'e9 94 8b 33 21 e2 d6 07 0f 54 ec 60 92 13 d4 17'
    )

    p = pd.start()
    print("P = " + to_hex(p))
