import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encryption_function(message,key):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(message) + encryptor.finalize()
    return iv + encryptor.tag + encrypted
def decryption_function(encrypted_message,key):
    iv = encrypted_message[:12]
    tag = encrypted_message[12:28]
    cipher_txt = encrypted_message[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    clean_message = decryptor.update(cipher_txt) + decryptor.finalize()
    return clean_message

