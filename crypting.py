import base64
import os
import sys
from abc import ABC, abstractmethod
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv
from getpass import getpass

import arg_parser
#from argparse import ArgumentParser

load_dotenv()

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


class Encrypter:

    def encrypt(self, msg_to_encrypt):
        fernet = self.make_fernet()
        return fernet.encrypt(msg_to_encrypt)

    def decrypt(self, msg_to_decrypt):
        try:
            fernet = self.make_fernet()
            return fernet.decrypt(msg_to_decrypt)
        except InvalidToken:
            print("Invalid password or salt. Decryption can't be done")
            sys.exit()

    def _generate_key(self):
        password = self.get_password()
        salt = self.get_salt()
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
        try:
            new_file = Path(filepath.parent, filepath.name + ".enc")
            with open(filepath, "r") as file:
                content = file.read()
            encrypted_content = process.make_process(content.encode("utf-8"))
            with open(new_file, "wb") as file:
                file.write(encrypted_content)
            if not arg_parser.args.keep_originals:
                filepath.unlink()
        except FileNotFoundError:
            print(f"File {filepath} not found")

    def decrypt_file(self, filepath: Path):
        """
        Function to decrypt file
        1) open file
        2) read content of file
        3) decrypt content
        4) save decrypted content to new file without .enc extension
        5) remove original file
        :param filepath:
        :return:
        """
        decrypt = Decrypt(self)
        process = CryptographProcess(decrypt)

        try:
            with open(filepath, "rb") as file:
                content = file.read()
            decrypted_content = process.make_process(content)
            decrypted_file = Path(filepath.parent, filepath.name[:-4])
            with open(decrypted_file, "wb") as file:
                file.write(decrypted_content)
            filepath.unlink()
        except FileNotFoundError:
            print(f"File {filepath} not found")

    def encrypt_folder(self, folder_path: Path):
        """
        1) In for loop goes to every file in directory
        2) Check if is file or directory
        3) If is file, call encrypt_file
        4) If is directory, call my own (encrypt_folder)
        :param folder_path:
        :return:
        """

        for element in os.scandir(folder_path):
            if not element.is_dir():
                self.encrypt_file(Path(element.path))
            else:
                self.encrypt_folder(Path(element.path))

    @staticmethod
    def get_password():
        password = None
        if arg_parser.args.password:
            while not password:
                password = getpass("Enter password")
            return password
        else:
            return os.getenv("PASSWORD")

    @staticmethod
    def get_salt():
        salt = None
        if arg_parser.args.salt:
            while not salt:
                salt = getpass("Enter salt")
            return salt
        else:
            return os.getenv("SALT")


class CryptographProcess:
    def __init__(self, command):
        self.command = command

    def make_process(self, message):
        return self.command.execute(message)

# ToDo make exception handling for KeyboardInterrupt