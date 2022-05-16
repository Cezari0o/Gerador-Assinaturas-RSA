from email.mime import base
from AES_encipher import CTR_Mode
from OAEP import *
from RSA_key_gen import AES_key_gen
from utility import bit_size
import base64
from math import ceil

class data_msg:
    """ Class that holds the values used in the data transfer. """

    def __init__(self, signature: bytes = None, msg: bytes = None, symmetric_key: bytes = None, nonce_val: int = None):
        self.signature = signature
        self.msg = msg
        self.symmetric_key = symmetric_key
        self.nonce_val = nonce_val # Used in the AES_CTR mode

    def from_base64(self, base64_str: str):
        dm = data_msg()

        d = vars(dm)
        lines = base64_str.split('\n')
        idx = 0

        for k in d.keys():
            d[k] = lines[idx]
            d[k] = base64.b64decode(d[k])
            idx += 1
        self.__dict__ = d

        self.nonce_val = int.from_bytes(self.nonce_val, byteorder='big')

    def int_to_byte(self, val):

        if type(val) != type(bytes()):
            l = ceil(bit_size(val) / 8)
            val = val.to_bytes(length=l, byteorder='big')

        return val

    def get_base64_encode(self):

        self.nonce_val = self.int_to_byte(self.nonce_val)

        my_vars = vars(self)

        result = str()
        for v in my_vars.values():
            if v == None:
                result += base64.b64encode(bytes()).decode('utf-8') + '\n'
            else:
                result += base64.b64encode(v).decode('utf-8') + '\n'

        self.nonce_val = int.from_bytes(self.nonce_val, byteorder='big')
        return result

class AES_message_cipher:
    """ Does the ciphering of a message, in bytes, of any size. """

    def __init__(self, key_bit_size = 128):
        self.__block_count__ = 16 # the block bytes count

        kg = AES_key_gen(key_bit_size)
        self.key = kg.generate_key()
        self.key = self.key.to_bytes(length=kg.bit_size // 8, byteorder='big')
    
    def encrypt(self, msg: bytes):

        blocks_count = ceil(len(msg) / self.__block_count__)

        dm = data_msg()
        cipher_blocks = []

        cipher = CTR_Mode(self.key)
        
        for i in range(blocks_count):

            idx = i * self.__block_count__
            if i == blocks_count - 1:
                b = msg[idx:]
            else:
                b = msg[idx:idx + self.__block_count__]

            b = cipher.encrypt_block(data=b)
            cipher_blocks += (b)

        cipher_blocks = bytes(cipher_blocks)
        dm.msg = cipher_blocks
        dm.symmetric_key = self.key
        dm.nonce_val = cipher.nonce

        return dm

class AES_message_decipher:
    """ Deciphers a message, in bytes, of any size. """

    def __init__(self):
        self.__block_count__ = 16 # the block bytes count

    def decrypt(self, dm: data_msg):

        blocks_count = ceil(len(dm.msg) / self.__block_count__)
        cipher = CTR_Mode(dm.symmetric_key, nonce=dm.nonce_val)

        msg = []
        for i in range(blocks_count):
            idx = i * self.__block_count__
            
            if i == blocks_count - 1:
                b = dm.msg[idx:]
            else:
                b = dm.msg[idx:idx + self.__block_count__]

            b = cipher.decrypt_block(b)
            msg += b

        msg = bytes(msg)

        return msg