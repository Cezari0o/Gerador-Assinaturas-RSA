from RSA_key_gen import key_pair
from data_msg import AES_message_cipher, AES_message_decipher, data_msg
from utility import hash_data, bit_size
from OAEP import RSA_OAEP_cipher, RSA_encrypt_decrypt
from math import ceil
from RSA_key_gen import key_gen

class person:

    def __init__(self, kp : key_pair = None):
        
        self.kp = kp

    def send_msg(self, msg: bytes, public_key: tuple, file_name: str):
        """ Write the message to the file. Public key should be in the form (n, e), 
        where n and e are the modulus and the public exponent from the receiver."""

        signature = int.from_bytes(hash_data(msg), byteorder='big')
        dm = AES_message_cipher(key_bit_size=128).encrypt(msg)

        # print(self.kp.private)
        private = (self.kp.n, self.kp.d)
        dm.signature = int(RSA_encrypt_decrypt(signature, private))

        dm.signature = dm.signature.to_bytes(
            length=ceil(bit_size(dm.signature) / 8), byteorder='big')

        pk = key_pair()
        pk.set_public(*public_key)
        dm.symmetric_key = RSA_OAEP_cipher(pk).encrypt(dm.symmetric_key)
        
        with open(file_name, mode='w+', encoding='utf-8') as file:
            file.write(dm.get_base64_encode())

    def receive_msg(self, public_key: tuple, file_name: str):
        """ Returns (equal_sign, msg), where equal_sign indicates if the signature is from the sender, 
        and msg is the message readed, in bytes. Reads the file from the sender. 
        Public key should be in the form (n, e), where n and e are the modulus and the public exponent 
        from the sender."""

        dm = data_msg()
        with open(file_name, mode='r', encoding='utf-8') as file:
            data = file.read()

        dm.from_base64(data)
        dm.signature = int.from_bytes(dm.signature, byteorder='big')
        dm.signature = RSA_encrypt_decrypt(dm.signature, public_key)
        dm.symmetric_key = RSA_OAEP_cipher(self.kp).decrypt(dm.symmetric_key)

        dm.msg = AES_message_decipher().decrypt(dm)

        msg_hash = hash_data(dm.msg)

        msg_hash = int.from_bytes(msg_hash, byteorder='big')
        return bool(msg_hash == dm.signature), dm.msg


class control:

    def __init__(self) -> None:
        self.group = []
    
    def create_person(self):
        self.group.append(person())

        return len(self.group) - 1
    
    def set_key(self, person_idx: int, kp: key_pair = None):

        if person_idx > len(self.group):
            raise Exception("Person index is out of range!")

        if kp == None:
            kp = key_gen().generate_key(bit_size=2048)

        self.group[person_idx].kp = kp

    def notify(self, sender: int, receiver: int, file_name: str):
        if sender > len(self.group) or receiver > len(self.group):
            raise Exception("Person index is out of range!")

        print(f"Notifying the message from person {sender} to {receiver}")
        pk = self.group[sender].kp.public
        self.group[receiver].receive_msg(pk, file_name)