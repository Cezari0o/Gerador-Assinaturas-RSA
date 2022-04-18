from utility import get_rows_form, get_columns_form, get_vector_form, get_xor
from random import SystemRandom

def mask(i):
    return i & 255
    
class AES_cipher:

    def __init__(self, key: bytes = None):
        self.encoding = 'utf-8'
        self.__sbox__ = self.__init_sbox__()
        self.__key__ = key

    def set_key(self, key:bytes):
        self.__key__ = key
        
    def __init_sbox__(self):
        sbox = 256 * [0]

        ROTL8 = lambda x, shift: (x << shift) | (x >> (8 - shift))
    
    
        p = q = 1

        while True:
            p = p ^ (p << 1) ^ (0x1b if p & 0x80 > 0 else 0)
            p = mask(p)
            
            q ^= (q << 1)
            q ^= (q << 2)
            q ^= (q << 4)
            q ^= (0x09 if q & 0x80 > 0 else 0)
    
            q = mask(q)
            
            xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q,4)
    
            sbox[p] = mask(xformed ^ 0x63)
    
            if p == 1:
                break
    
            sbox[0] = 0x63

        return bytes(sbox)
    
    def __convert_to_bytes__(self, data: str):

        bytes_to_return = bytes(data, self.encoding)

        return bytes_to_return

    def __subst_bytes__(self, some_bytes: bytes):
        return some_bytes.translate(self.__sbox__) 

    def __shift_rows__(self, some_bytes: bytes):
        
        byte_lines = []
        for i in range(4):
            byte_lines.append(some_bytes[i*4:i*4+4])

        for shift, line in enumerate(byte_lines):
            line = line[shift:] + line[:shift]
            byte_lines[shift] = line

        shifted_bytes = []
        for line in byte_lines:
            shifted_bytes += line

        return shifted_bytes


    def __mix_columns__(self, some_bytes: bytes):

        def gmix_column(r):
            a = 4*[0]
            b = 4*[0]
    
            h = 0

            for c in range(4):
                a[c] = r[c]
                h = (r[c] >> 7) & 1
                b[c] = r[c] << 1
                b[c] ^= h * 0x1B
            
            r[0] = mask(b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1])
            r[1] = mask(b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2])
            r[2] = mask(b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3])
            r[3] = mask(b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0])

            return r

        temp_bytes = get_columns_form(some_bytes, 4)

        result = []

        for col in temp_bytes:
            result.append(gmix_column(col))

        return get_vector_form(result, form = "column")

    def __add_round_key__(self, some_bytes: bytes, round_key: bytes):
        
        sb_col = get_columns_form(some_bytes, 4)
        rk_col = round_key

        result = []
        for idx, c in enumerate(sb_col):
            result.append([n ^ rk_col[idx][i] for i, n in enumerate(c)])

        return bytes(get_vector_form(result, form = "column"))
        
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

    def __get_rounds_count__(self, key: bytes):

        bytes_count = len(key)
        if bytes_count == 16:
            return 10

        elif bytes_count == 24:
            return 12

        elif bytes_count == 32:
            return 14

        return 0
        
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

        round_keys = [bytes(w) for w in key2]

        rcons = self.__get_rcon__()
        
        for i in range(4 * rounds_count):
            if i < word_count:
                continue
            elif i % word_count == 0:
                op_key = self.__subst_bytes__(rot_word(round_keys[i - 1]))

                res = get_xor(round_keys[i - word_count], op_key)
                res = get_xor(res, rcons[i // word_count - 1])
                round_keys.append(res)

            elif word_count > 6 and i % word_count == 4:
                round_keys.append(get_xor(round_keys[i - word_count], self.__subst_bytes__(round_keys[i - 1])))
            
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
        
    def encrypt(self, data: bytes):
        
        bytes_count = len(data)
        if bytes_count > 16:
            raise Exception("Size of data to large")

        if self.__key__ == None:
            raise Exception("Key is not set!")

        round_keys = self.__key_schedule__(self.__key__)
        
        rounds_count = self.__get_rounds_count__(self.__key__)

        # Round 0
        state = self.__add_round_key__(data, round_keys[0])

        # Round 1 to rounds_count - 1
        for i in range(1, rounds_count):
            state = self.__subst_bytes__(state)
            state = self.__shift_rows__(state)
            state = self.__mix_columns__(state)
            state = self.__add_round_key__(state, round_keys[i])

        # Last round
        state = self.__subst_bytes__(state)
        state = self.__shift_rows__(state)
        state = self.__add_round_key__(state, round_keys[-1])

        return state

class CTR_Mode:

    def __init__(self, key = None):
        self.nonce = self.generate_nonce()
        self.cipher = AES_cipher(key)
        self.__counter__ = 0
        
    def generate_nonce(self):
        lower_bound = 0
        upper_bound = 2**64

        generator = SystemRandom()
        nonce_value = generator.randrange(lower_bound, upper_bound)

        return nonce_value

    def encrypt_block(self, data: bytes):

        if len(data) > 16:
            raise Exception("Data too large! I need 16 bytes")
    
        ctr_value = (self.nonce << 64) | self.__counter__

        self.__counter__ += 1

        ctr = ctr_value.to_bytes(length = 16, byteorder = "big")
        state = self.cipher.encrypt(ctr)

        return get_xor(data, state)        