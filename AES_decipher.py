from utility import get_columns_form, get_vector_form, get_rows_form, get_xor, gmul, mask
from AES_encipher import AES_cipher

class AES_decipher:

    def __init__(self, key: bytes = None):
        self.encoding = 'utf-8'
        self.__sbox__ = self.__init_sbox__()
        self.__key__ = key

    def set_key(self, key:bytes):
        self.__key__ = key


    def __inv_shift_rows__(self, some_bytes: bytes):
        
        byte_lines = []
        for i in range(4):
            byte_lines.append(some_bytes[i*4:i*4+4])

        for shift, line in enumerate(byte_lines):
            line = line[4 -shift:] + line[:4 -shift] # orig
            # line = line[:shift] + line[shift:]

            byte_lines[shift] = line

        shifted_bytes = []
        for line in byte_lines:
            shifted_bytes += line

        return bytes(shifted_bytes)

    def __init_sbox__(self):

        return bytes([0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d])

    def __inv_subst_bytes__(self, some_bytes: bytes):
        return some_bytes.translate(self.__sbox__)


    def __add_round_key__(self, some_bytes: bytes, round_key: bytes):
        
        sb_col = get_columns_form(some_bytes, 4)
        rk_col = round_key

        result = []
        for idx, c in enumerate(sb_col):
            result.append([n ^ rk_col[idx][i] for i, n in enumerate(c)])

        return bytes(get_vector_form(result, form = "column"))

    
    def __get_rounds_count__(self, key: bytes):

        bytes_count = len(key)
        if bytes_count == 16:
            return 10

        elif bytes_count == 24:
            return 12

        elif bytes_count == 32:
            return 14

        return 0

    
    def col_multiply(self, col):
        consts = [0xe, 0xb, 0xd, 0x9]

        r = []
        for i in range(4):
            r.append( gmul(col[0], consts[-i]) ^ gmul(col[1], consts[(1 -i) % 4]) ^ gmul(col[2], consts[(-i + 2) % 4]) ^ gmul(col[3], consts[(-i + 3) % 4]) )
            # print(bytes(consts).hex(','))

        return r

        
    def __inv_mix_columns__(self, some_bytes: bytes):

        temp_bytes = get_columns_form(some_bytes, 4)

        result = []

        for col in temp_bytes:
            result.append(self.col_multiply(col))

        return get_vector_form(result, form = "column")

    def __get_rcon__(self, key_size: int = 128):
        
        # Uses up to 10 rcons in the AES
        rcons = 10 * [[]]

        for idx in range(len(rcons)):
            
            if idx == 0:
                rcons[idx] = 4 * [0]
                rcons[idx][0] = 1

            elif rcons[idx - 1][0] < 0x80:
                rcons[idx] = 4 * [0]
                rcons[idx][0] = mask(rcons[idx -1][0] << 1)
                
            else:
                rcons[idx] = 4*[0]
                rcons[idx][0] = mask((rcons[idx -1][0] << 1) ^ 0x11b)
                

        return rcons

    def __key_schedule__(self, key: bytes):
        """ Returns the key expanded. Returns a list, 
        where every item is a block, and every block have 4 32-bit word, representing 
        a rounded key. Every word is a column of the rounded key """
        round_keys = []
        
        def rot_word(word: bytes):
            return bytes(word[1:] + word[:1])
        def get_xor(w1: bytes, w2: bytes):
            result = []

            for idx, b in enumerate(w1):
                result.append(b ^ w2[idx])

            return bytes(result)
        
        key2 = get_columns_form(key, row_size = 4)
        word_count = len(key2) # Number of 32-bit words
        rounds_count = self.__get_rounds_count__(key) + 1

        cip = AES_cipher()
        round_keys = [bytes(w) for w in key2]

        rcons = self.__get_rcon__()
        
        for i in range(4 * rounds_count):
            if i < word_count:
                continue
            elif i % word_count == 0:
                op_key = cip.__subst_bytes__(rot_word(round_keys[i - 1]))

                res = get_xor(round_keys[i - word_count], op_key)
                res = get_xor(res, rcons[i // word_count - 1])
                round_keys.append(res)

            elif word_count > 6 and i % word_count == 4:
                round_keys.append(get_xor(round_keys[i - word_count], cip.__subst_bytes__(round_keys[i - 1])))
            
            else:        
                round_keys.append(get_xor(round_keys[i - word_count], round_keys[i - 1]))
                

        
        keys_result = []

        block = []
        for idx, k in enumerate(round_keys):
            block.append(k)
            if (idx + 1) % 4 == 0:
                keys_result.append(block)
                block = []

        return keys_result


    def decrypt(self, data: bytes):
        
        bytes_count = len(data)
        if bytes_count > 16:
            raise Exception("Size of data to large")

        if self.__key__ == None:
            raise Exception("Key is not set!")

        round_keys = self.__key_schedule__(self.__key__)
        rounds_count = self.__get_rounds_count__(self.__key__)

        dw = len(round_keys) * [[]]
        for idx, w in enumerate(round_keys):
            if idx == 0 or idx == rounds_count:
                dw[idx] = w
            else:
                inv_w = []
                for word in w:
                    inv_w.append(bytes(self.col_multiply(word)))

                dw[idx] = inv_w

        dw.reverse()
        round_keys = dw

        # Round 0
        state = self.__add_round_key__(data, round_keys[0])

        # Round 1 to rounds_count - 1
        for i in range(1, rounds_count):
            state = self.__inv_subst_bytes__(state)
            state = self.__inv_shift_rows__(state)
            state = self.__inv_mix_columns__(state)
            state = self.__add_round_key__(state, round_keys[i])

        # Last round
        state = self.__inv_subst_bytes__(state)
        state = self.__inv_shift_rows__(state)
        state = self.__add_round_key__(state, round_keys[-1])

        return state
        
