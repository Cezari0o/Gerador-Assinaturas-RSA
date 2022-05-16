from math import ceil, log2
from hashlib import sha3_512 as SHA_hash

def mask(i):
    return i & 255

def bit_size(n):
    return ceil(log2(n + 1)) 


def get_rows_form(vector, row_size):
    matrix = []

    temp = []
    for idx, item in enumerate(vector):
        temp.append(item)

        if (idx + 1) % row_size == 0:
            matrix.append(temp)
            temp = []

    if len(temp) > 0:
        matrix.append(temp)
    
    return matrix

def get_columns_form(vector, row_size):
    
    mat_size = row_size
    matrix = []
    for i in range(mat_size):
        matrix.append([])
    for idx, item in enumerate(vector):
        matrix[(idx % mat_size)].append(item)
    
    return matrix

def get_vector_form(matrix, form = "row"):
    vector = []
    
    if form == "row":
        for row in matrix:
            vector += row

    else:
        vector = len(matrix) * len(matrix[0]) * [0]

        for idx in range(len(vector)):
            vector[idx] = matrix[idx % len(matrix)][idx // len(matrix)]
    
    return vector

def get_xor(w1: bytes, w2: bytes, order = 'big'):
    result = []

    if len(w1) > len(w2):
        temp = w1
        w1 = w2
        w2 = temp 

    # if len(w1) != len(w2):
    #     raise Exception("Error! Words differs in size!")
    
    if order == 'big':
        for idx, b in enumerate(w1):
            result.append(b ^ w2[idx])

    else:
        for idx in range(len(w1) - 1, -1, -1): 
            result.append(w1[idx] ^ w2[idx])
    
        result = reversed(result)
    

    return bytes(result)

def xtime(b: int):
    """ b: integer in the range 0-255"""

    ans = (b << 1)

    # Checking if the MSB is 1
    bit_7 = (b >> 7) & 1

    ans ^= bit_7 * 0x1b

    return mask(ans)

def gmul_2(b, pow_2: int):

    if pow_2 == 2:
        return xtime(b)

    if pow_2 == 1:
        return b

    return xtime(gmul_2(b, pow_2 >> 1))

def gmul(b: int, c: int):

    ans = 0
    for p in range(0, bit_size(c)):

        if (1 << p) & c != 0:
            ans ^= gmul_2(b, (1 << p))

    return ans

def to_bytes(msg : str):
    """ Returns the msg to bytes form."""
    
    return bytes(msg, encoding='utf-8')

def from_bytes(msg: bytes):
    """ Returns the msg to a string format"""

    return msg.decode(encoding='utf-8')

def hash_data(data: bytes):
    hasher = SHA_hash()

    hasher.update(data)
    return hasher.digest()