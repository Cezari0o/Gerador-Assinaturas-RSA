
from hashlib import sha3_512 as SHA_hash
# from hashlib import sha1 as SHA_hash
from math import ceil, floor
from os import urandom
from utility import get_xor, bit_size, hash_data
from RSA_key_gen import key_pair


def mask_gen_func(data : bytes, size : int):

    hash_obj = SHA_hash()
    
    if size > (1 << 32) * hash_obj.digest_size:
        raise Exception(f"Mask of size {size} will be to long")

    full_mask = bytes()

    for i in range(0, ceil(size/hash_obj.digest_size)):
        hash_obj = SHA_hash()
        
        c = i.to_bytes(length=4, byteorder='big')
        
        temp = bytes()
        temp = data + c

        hash_obj.update(temp)
        
        full_mask += hash_obj.digest()

    mask = full_mask[0:size]
    return mask


def OAEP_encode(msg: bytes, output_size : int, encode_param: bytes = None):

    hash_obj = SHA_hash()

    # print(len(msg), output_size, hash_obj.digest_size)
    if len(msg) > output_size - 2 * hash_obj.digest_size -1:
        raise Exception("Message to long!")

    # Padding zeros
    ps = bytes(output_size - len(msg) -2*hash_obj.digest_size - 1)

    if encode_param == None:
        encode_param = bytes()
        
    p_hash = hash_data(encode_param)

    # alo
    # print(len(p_hash))
    
    DB = bytes()
    DB = p_hash + ps + int(1).to_bytes(length = 1, byteorder='big') + msg
    # DB = p_hash + ps + msg

    # alo
    # print(DB.hex(' '))
    # seed = bytes([0xaa, 0xfd, 0x12, 0xf6, 0x59, 0xca, 0xe6, 0x34, 0x89, 0xb4, 0x79, 0xe5, 0x07, 0x6d, 0xde, 0xc2, 0xf0, 0x6c, 0xb5, 0x8f])
    # print(len(seed))
    seed = urandom(hash_obj.digest_size)

    db_mask = mask_gen_func(seed, output_size - hash_obj.digest_size)
    # alo
    # print(db_mask.hex(' '))
    # print(len(DB), len(db_mask))
    masked_db = get_xor(DB, db_mask, order='little')
    # print(masked_db.hex(' '))

    seed_mask = mask_gen_func(masked_db, hash_obj.digest_size)

    masked_seed = get_xor(seed, seed_mask)

    encoded_msg = bytes()
    encoded_msg = masked_seed + masked_db

    return (encoded_msg)


def OAEP_decode(msg: bytes, encode_param: bytes = None):

    hash_obj = SHA_hash()
    dg_size = hash_obj.digest_size
    
    if len(msg) < (dg_size << 1) + 1:
        raise Exception("Decoding error!")

    masked_seed = msg[0:dg_size]
    masked_db = msg[dg_size:]

    seed_mask = mask_gen_func(masked_db, dg_size)
    seed = get_xor(masked_seed, seed_mask)

    db_mask = mask_gen_func(seed, len(msg) - dg_size)

    db = get_xor(masked_db, db_mask)

    if encode_param == None:
        encode_param = bytes()
        
    p_hash = hash_data(encode_param)

    tp_hash = db[0:dg_size]

    for i in range(dg_size, len(db)):
        if db[i] != 0:
            b_idx = i
            break

    if db[b_idx] != 1:
        raise Exception("Decoding error!")

    if tp_hash != p_hash:
        raise Exception("Decoding error!")

    return db[b_idx + 1:]


def RSA_encrypt_decrypt(msg: int, key : tuple):
    """ Does the msg ^ exponent (mod n), where exponent is the private or public exponent. The key should be in the form (n, exponent). """
    
    n, exponent = key

    if not (0 <= msg < n):
        raise Exception("Message representative out of range!")

    cipher_rep = pow(msg, exponent, n)
    return cipher_rep

class RSA_OAEP_cipher:

    def __init__(self, kp: key_pair = None):

        self.kp = kp

    def __get_modulus_size__(self):
        if self.kp == None:
            raise Exception("Key is not set!")

        return ceil(bit_size(self.kp.n) / 8)
        

    def __RSA_encryption__(self, msg: int, sign = False):

        if self.kp == None:
            raise Exception("Key is not set!")
        
        if not 0 <= msg < self.kp.n:
            raise Exception("Message representative out of range!")

        if sign:
            cipher_rep = pow(msg, self.kp.d, self.kp.n)

        else:
            cipher_rep = pow(msg, self.kp.e, self.kp.n)
        return cipher_rep

    def __RSA_decryption__(self, cipher_msg: int, sign = False):

        if self.kp == None:
            raise Exception("Key is not set!")

        if not 0 <= cipher_msg < self.kp.n:
            raise Exception("Message representative out of range!")

        if sign:
            msg = pow(cipher_msg, self.kp.e, self.kp.n)
        else:
            msg = pow(cipher_msg, self.kp.d, self.kp.n)

        return msg

    def sign_msg(self, msg: bytes):

        msg_int = int.from_bytes(msg, byteorder='big')
        sign_int = self.__RSA_encryption__(msg_int, sign=True)

        return sign_int.to_bytes(length=self.__get_modulus_size__(), byteorder='big')

    def get_sign_from_msg(self, signature: bytes):

        sign_int = int.from_bytes(signature, byteorder='big')

        msg_int = self.__RSA_decryption__(sign_int, sign=True)

        return msg_int.to_bytes(length=self.__get_modulus_size__(), byteorder='big')
    
    def msg_max_size(self):
        """ Returns the max supported data size, in bytes. """

        hash_obj = SHA_hash()

        return self.__get_modulus_size__() - 2 - 2*hash_obj.digest_size 
    
    def encrypt(self, msg: bytes, encode_param: bytes = None):

        enc_msg = OAEP_encode(msg, self.__get_modulus_size__() - 1, encode_param)

        msg_int = int.from_bytes(enc_msg, byteorder='big')

        cipher_int = self.__RSA_encryption__(msg_int)

        cipher_text = cipher_int.to_bytes(length = self.__get_modulus_size__(), byteorder='big')

        return cipher_text

    def decrypt(self, cipher_text: bytes, encode_param: bytes = None):

        if len(cipher_text) != self.__get_modulus_size__():
            raise Exception("Decryption error!")

        cipher_int = int.from_bytes(cipher_text, byteorder='big')

        try:
            # msg_int = self.__RSA_decryption__(cipher_int)
            msg_int = RSA_encrypt_decrypt(msg=cipher_int, key=self.kp.private)
        except:
            raise Exception("Decryption error!")

        try:
            # print(msg_int)
            enc_msg = msg_int.to_bytes(length = self.__get_modulus_size__() - 1, byteorder='big')
        except:
            raise Exception("Decryption error!")
    
        try:
            msg = OAEP_decode(enc_msg, encode_param)
        except:
            raise Exception("Decryption error!")

        return msg
        