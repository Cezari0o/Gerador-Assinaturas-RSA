from random import randrange, SystemRandom
from math import gcd, ceil

# from modulo import modulo

def get_primes(max_count):
    # Return a list of primes, from 2 to max_count
    primes_list = []
    
    division_list = [0 for i in range(max_count + 1)]

    for n in range(2, max_count + 1):

        if division_list[n] == 0:
            primes_list.append(n)

            for it in range(n, max_count + 1, n):
                division_list[it] = 1

    return primes_list


def extended_gcd(a, b):
    """ Returns (gcd, x, y), such that a.x + b.y == gcd """
    s = 0
    t = 1
    r = b

    old_s = 1
    old_t = 0
    old_r = a
    
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t 

    gcd = old_r
    x = old_s
    y = old_t
    return gcd, x, y

class key_pair:

    def __init__(self):
        self.n = self.p = self.q = self.d = self.e = 0
        self.private = self.public = ()
    
    def set_private(self, n, p, q, d):
        self.n, self.p, self.q, self.d = n, p, q, d
        self.private = (n, p, q, d)

    def set_public(self, n, e):
        self.public = (n, e)

        self.n, self.e = self.public
    

    
class key_gen:
    
    def __init__(self):
        
        self.__max_primes_range__ = 20000 # The maximum range to collect primes 

        self.__primes__ = get_primes(self.__max_primes_range__)

    def __is_prime__(self, p):

        for p_i in self.__primes__:
            if p % p_i == 0:
                return False

        return True

    def __get_odd_form__(self, num):

        expo_2 = 0
        odd_factor = num - 1
        while odd_factor % 2 == 0:
            expo_2 += 1
            odd_factor //= 2

        return (expo_2, odd_factor)

    def generate_prime_number(self, lower_bound, upper_bound, e : int = None):
        # returns a (probable) prime number p 

        continue_loop = True
        reset_loop = False
        p = 0
        rg = SystemRandom() # A Random generator, secure to use in this context
        while continue_loop:
            continue_loop = False

            if reset_loop:
                p += 2
                reset_loop = False
            else:
                p = rg.randrange(lower_bound - 2, upper_bound - 1)
            
            if p % 2 == 0:
                continue_loop = True
                reset_loop = False
                continue    

            if not self.__is_prime__(p):
                continue_loop = True
                reset_loop = True
                continue

            if e != None and gcd(p - 1, e) != 1:
                reset_loop = True
                continue_loop = True
                continue

            expo_2, odd_factor = self.__get_odd_form__(p)
            
            # print(2**expo_2*odd_factor + 1 == p)
            for i in range(4):
                rand_num = rg.randrange(1, p - 1)

                # print(rand_num)
                # print("passei")
                b = pow(rand_num, odd_factor, p)
                # print("passei")

                if continue_loop:
                    break
                    
                if b != 1 and b != p - 1:
                    j = 0

                    while b != p - 1:
                        j+= 1

                        if j == expo_2:
                            continue_loop = True
                            reset_loop = True
                            break

                        b = pow(b, 2, p)
                        
                        if b == 1:
                            continue_loop = True
                            reset_loop = True
                            break

            
            if p > upper_bound:
                reset_loop = False
                continue_loop = True

        return p

    def __get_bounds__(self, bit_size):

        expo = ceil(bit_size / 2)

        lower_bound = 2**(expo - 1)
        upper_bound = 2**expo - 1

        return lower_bound, upper_bound

    def generate_key(self, bit_size, e = None):

        # lower_bound = floor(2**((bit_size - 1) / 2)) + 1 # <- Arrumar
        # upper_bound = ceil(2**(bit_size/2)) - 1

        lower_bound, upper_bound = self.__get_bounds__(bit_size)
        
        if e == None or e >= lower_bound:
            e = 65537 # 2**16 +1, a prime number

        prime_p = self.generate_prime_number(lower_bound, upper_bound, e)

        prime_q = self.generate_prime_number(lower_bound, upper_bound, e)

        n = prime_p * prime_q

        keys = key_pair()

        keys.set_public(n, e)

        phi = (prime_p - 1) * (prime_q - 1)
        d = extended_gcd(phi, e)[2]

        d = d % phi
        keys.set_private(n, prime_p, prime_q, d)

        return keys


class AES_key_gen:
    """ Generates a key to be used in the AES algorithm. Bit_size can be 128, 192 or 256. If different, generates 128-bit key """

    def __init__(self, bit_size = 128):

        sizes = [128, 192, 256]

        change = True
        for s in sizes:
            if s == bit_size:
                change = False

        if change:
            bit_size = 128
        
        self.lower_bound = (1 << bit_size - 1)
        self.upper_bound = (1 << (bit_size))

    def generate_key(self):
        
        rg = SystemRandom()

        key = rg.randrange(self.lower_bound, self.upper_bound)

        return key
