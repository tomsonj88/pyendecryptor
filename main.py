import argparse
import base64

from abc import ABC, abstractmethod
from argparse import ArgumentParser

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import arg_parser
from pathlib import Path

class Command(ABC):

    @abstractmethod
    def execute(self, message):
        pass


class Encrypt(Command):

    def __init__(self, szyfrator):
        self.szyfrator = szyfrator

    def execute(self, message):
        return self.szyfrator.encrypt(message)


class Decrypt(Command):

    def __init__(self, szyfrator):
        self.szyfrator = szyfrator

    def execute(self, encrypted_msg):
        return self.szyfrator.decrypt(encrypted_msg)


class Szyfrator:

    def encrypt(self, msg_to_encrypt):
        fernet = self.make_fernet()
        return fernet.encrypt(msg_to_encrypt)

    def decrypt(self, msg_to_decrypt):
        fernet = self.make_fernet()
        return fernet.decrypt(msg_to_decrypt)

    @staticmethod
    def _generate_key():
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                         salt=salt.encode(), iterations=480000)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def make_fernet(self):
        key = self._generate_key()
        return Fernet(key)

    def encrypt_file(self, filepath: Path):
        """
        Function to encrypt file
        1) open file
        2) read content of file
        3) encrypt content
        4) save encrypted content to new file with .enc extension
        5) remove original file if -ko flag is set to False
        :param filepath: Path
        :return:
        """
        encrypt = Encrypt(self)
        process = CryptographProcess(encrypt)
        #filename = filepath.name
        new_file = Path(filepath.parent, filepath.name + ".enc")
        with open(filepath, "r") as file:
            content = file.read()
        encrypted_content = process.make_process(content.encode("utf-8"))
        with open(new_file, "wb") as file:
            file.write(encrypted_content)
        if not arg_parser.args.keep_originals:
            filepath.unlink()


class CryptographProcess:
    def __init__(self, command):
        self.command = command

    def make_process(self, message):
        return self.command.execute(message)



#message = b"wakacje w Polsce"
password = "my_password399"
salt = "657"
# kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt.encode(), iterations=480000)
# key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
# f = Fernet(key)


cipher = Szyfrator()
encrypt = Encrypt(cipher)
#print(encrypt)
decrypt = Decrypt(cipher)
process = CryptographProcess(encrypt)
a = process.make_process(b"alladyn")
print(a)
process = CryptographProcess(decrypt)
b = process.make_process(a)
print(b.decode('utf-8'))
file_pth = Path("test.txt")
print(cipher.encrypt_file(file_pth))
