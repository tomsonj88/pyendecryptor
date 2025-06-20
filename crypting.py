import base64
import os
import sys
import time
from abc import ABC, abstractmethod
from pathlib import Path

from arg_parser import args
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv
from getpass import getpass
from tqdm import tqdm

load_dotenv()


class Command(ABC):

    @abstractmethod
    def execute(self, message):
        pass


class NotEncryptedFileError(Exception):
    pass


class NotAFileError(Exception):
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

    def encrypt_file(self, filepath: Path, destination_path: Path = None):
        """
        Function to encrypt file
        1) open file
        2) read content of file
        3) encrypt content
        4) save encrypted content to new file with .enc extension
        5) remove original file if -ko flag is set to False
        :param destination_path:
        :param filepath: Path
        :return:
        """
        encrypt = Encrypt(self)
        process = CryptographProcess(encrypt)
        try:
            self.check_path_is_file(filepath)
            if destination_path:
                if not self.is_path_exist(destination_path):
                    self.create_path(destination_path)
                new_file = Path(destination_path, filepath.name + ".enc")
            else:
                new_file = Path(filepath.parent, filepath.name + ".enc")
            with open(filepath, "rb") as file:
                content = file.read()
            encrypted_content = process.make_process(content)
            with open(new_file, "wb") as file: #ToDo: jak wbyeirasz destination_path nowa/nieistniejace to wywala bląd  FileNotFoundError
                file.write(encrypted_content)
            if not args.keep_originals:
                filepath.unlink()
                self.remove_dir_if_is_empty(filepath.parent) # todo: add to more functions
            if args.verbose == 1:
                print(f"File: {filepath} has been encrypted")
        except FileNotFoundError:
            print(f"File {filepath} not found")
        except NotAFileError as exception:
            print(exception)

    def decrypt_file(self, filepath: Path, destination_path: Path = None):
        """
        Function to decrypt file
        1) open file
        2) read content of file
        3) decrypt content
        4) save decrypted content to new file without .enc extension
        5) remove original file
        :param destination_path:
        :param filepath:
        :return:
        """
        # ToDo check if file end with ".enc", then decryption can be done
        decrypt = Decrypt(self)
        process = CryptographProcess(decrypt)
        #file_name = filepath.name
        try:
            self.check_path_is_file(filepath)
            if not filepath.name.endswith(".enc"):  # ToDo: zlikwidować file_name raczej
                raise NotEncryptedFileError(
                    f"File {filepath} is not encrypted. Decryption can't be done.")

            if destination_path:
                if not self.is_path_exist(destination_path):
                    self.create_path(destination_path)
                decrypted_file = Path(destination_path, filepath.name[:-4])
            else:
                decrypted_file = Path(filepath.parent, filepath.name[:-4])

            with open(filepath, "rb") as file:
                content = file.read()
            decrypted_content = process.make_process(content.decode("utf-8"))
            with open(decrypted_file, "wb") as file:
                file.write(decrypted_content)
            if not args.keep_originals:
                filepath.unlink()
                self.remove_dir_if_is_empty(filepath.parent) # todo: add to more functions
            if args.verbose == 1:
                print(f"File: {filepath} has been decrypted")
        except FileNotFoundError:
            print(f"File {filepath} not found")
        except NotEncryptedFileError as e:
            print(e)
        except NotAFileError as exception:
            print(exception)

    def encrypt_files(self, files: list, destination_path: Path = None):
        # for file in tqdm(files, desc="encrypting files"):
        iterable = tqdm(files) if args.verbose >= 3 else files
        for file in iterable:
            start_time = time.time()
            self.encrypt_file(Path(file), destination_path)
            end_time = time.time()
            # time.sleep(0.5)
            # print("\n")
            if args.verbose == 2:
                print(f"\nFile: {file} has been encrypted in {round(end_time - start_time, 3)} seconds")
            if args.verbose >= 3:
                tqdm.write(
                    f"File: {file} has been encrypted in {round(end_time - start_time, 3)} seconds")

    def decrypt_files(self, files: list, destination_path: Path = None):
        iterable = tqdm(files) if args.verbose >= 3 else files
        for file in iterable:
            start_time = time.time()
            self.decrypt_file(Path(file), destination_path)
            end_time = time.time()
            if args.verbose == 2:
                print(f"\nFile: {file} has been encrypted in {round(end_time - start_time, 3)} seconds")
            if args.verbose >= 3:
                tqdm.write(f"File: {file} has been encrypted in {round(end_time - start_time, 3)} seconds")

    def encrypt_folder(self, folder_path: Path, destination_path: Path = None): # TODO: add dest path
        """
        1) In for loop goes to every file in directory
        2) Check if is file or directory
        3) If is file, call encrypt_file
        4) If is directory, call my own (encrypt_folder)
        :param folder_path:
        :return:
        """
        try:
            self.check_path_is_directory(folder_path)
            if destination_path:
                if not self.is_path_exist(destination_path):
                    self.create_path(destination_path)
            for element in os.scandir(folder_path):
                if not element.is_dir():
                    self.encrypt_file(Path(element.path), destination_path)
                else:
                    self.encrypt_folder(Path(element.path), destination_path)
            if args.verbose == 1:
                print(f"Folder: {folder_path} has been encrypted")
        except NotADirectoryError as exception:
            print(exception)

    def decrypt_folder(self, folder_path: Path, destination_path: Path = None): # TODO: add dest path
        try:
            self.check_path_is_directory(folder_path)
            if destination_path:
                if not self.is_path_exist(destination_path):
                    self.create_path(destination_path)
            for element in os.scandir(folder_path):
                if not element.is_dir():
                    self.decrypt_file(Path(element.path), destination_path)
                else:
                    self.decrypt_folder(Path(element.path), destination_path)
            if args.verbose == 1:
                print(f"Folder: {folder_path} has been decrypted")
        except NotADirectoryError as exception:
            print(exception)

    def encrypt_folders(self, folders: list, destination_path: Path = None):
        iterable = tqdm(folders) if args.verbose >= 3 else folders
        for folder in iterable:
            start_time = time.time()
            self.encrypt_folder(Path(folder), destination_path)
            end_time = time.time()
            if args.verbose == 2:
                print(f"Folder: {folder} has been encrypted in {round(end_time - start_time, 3)} seconds")
            if args.verbose >= 3:
                tqdm.write(
                    f"Folder: {folder} has been encrypted in {round(end_time - start_time, 3)} seconds")

    def decrypt_folders(self, folders: list, destination_path: Path = None):
        iterable = tqdm(folders) if args.verbose >= 3 else folders
        for folder in iterable:
            start_time = time.time()
            self.decrypt_folder(Path(folder), destination_path)
            end_time = time.time()
            if args.verbose == 2:
                print(f"Folder: {folder} has been decrypted in {round(end_time - start_time, 3)} seconds")
            if args.verbose >= 3:
                tqdm.write(
                    f"Folder: {folder} has been decrypted in {round(end_time - start_time, 3)} seconds")

    def encrypt_message(self, text: str) -> str:
        """
        Method to encrypt message/text.
        :param text:
        :return: bytes
        """
        encrypt = Encrypt(self)
        process = CryptographProcess(encrypt)
        return process.make_process(text.encode("utf-8")).decode("utf-8")

    def decrypt_message(self, encrypted_text: bytes) -> str:
        """
        Method to decrypt message/text.
        :param encrypted_text:
        :return: str
        """
        decrypt = Decrypt(self)
        process = CryptographProcess(decrypt)
        return process.make_process(encrypted_text).decode("utf-8")

    @staticmethod
    def get_password():
        password = None
        if args.password:
            while not password:
                password = getpass("Enter password")
            return password
        else:
            return os.getenv("PASSWORD")

    @staticmethod
    def get_salt():
        salt = None
        if args.salt:
            while not salt:
                salt = getpass("Enter salt")
            return salt
        else:
            return os.getenv("SALT")

    @staticmethod
    def check_path_is_directory(path: Path):
        if not os.path.isdir(path):
            raise NotADirectoryError(
                "Given location is not a directory or directory doesn't exist")

    @staticmethod
    def check_path_is_file(path: Path):
        if not os.path.isfile(path):
            raise NotAFileError(
                "Given location is not a file or file doesn't exist")

    def is_path_exist(self, path) -> bool:
        return os.path.exists(path)

    def create_path(self, path):
        os.mkdir(path)

    @staticmethod
    def remove_dir_if_is_empty(path):
        if not os.listdir(path):
            os.rmdir(path)


class CryptographProcess:
    def __init__(self, command):
        self.command = command

    def make_process(self, message):
        return self.command.execute(message)

# ToDo make exception handling for KeyboardInterrupt
