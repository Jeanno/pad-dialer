class NoSolutionException(Exception):
    pass

class PaddingDialer:

    BYTE_MAX = 255
    def __init__(self):
        self.encrypted_bytes = None
        self.iv = None
        self.block_size_in_byte = 128 // 8


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
        num_block = len(self.encrypted_bytes) // self.block_size_in_byte
        result = bytearray(self.get_block(0))
        for i in range(1, num_block):
            result += self.solve_block(self.get_block(i - 1), self.get_block(i))
        return result

    def solve_block(self, prev_block, target_block):
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
        dial_block = bytearray(prev_block)

        last_byte_candidates = []
        for i in range(self.BYTE_MAX + 1):
            dial_block[self.block_size_in_byte - 1] = i
            if self.check_padding(dial_block + target_block):
                last_byte_candidates.append(i)

        assert len(last_byte_candidates) == 1 or len(last_byte_candidates) == 2

        for c in last_byte_candidates:
            try:
                return self._solve_block_with_candidate(prev_block, target_block, c)
            except NoSolutionException:
                pass

        raise NoSolutionException



    def _solve_block_with_candidate(self, prev_block, target_block, last_byte_candidate):
        dial_block = bytearray(prev_block)
        dial_block[self.block_size_in_byte - 1] = last_byte_candidate
        for i in reversed(range(self.block_size_in_byte - 1)):
            set_to = self.block_size_in_byte - i
            for j in range(i + 1, self.block_size_in_byte):
                dial_block[j] ^= set_to ^ (set_to - 1)

            count = 0
            while True:
                dial_block[i] = (dial_block[i] + 1) % (self.BYTE_MAX + 1)
                if self.check_padding(dial_block + target_block):
                    break

                count += 1
                if count > self.BYTE_MAX + 1:
                    raise Exception("Cannot dial to right padding")


        plaintext = bytes(d ^ p ^ self.block_size_in_byte for (d, p) in zip(dial_block, prev_block))
        return plaintext


    def check_padding(self, byte_ary):
        raise NotImplementedError


    def cal_num_blocks(self):
        if len(self.encrypted_bytes) % self.block_size_in_byte != 0:
            raise Exception("Last block of encrypted bytes is incomplete")

        return len(self.encrypted_bytes) / self.block_size_in_byte


def to_hex(byte_ary):
    return ''.join(format(x, '02x') for x in byte_ary)
