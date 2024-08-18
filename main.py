import argparse
import os

from dotenv import load_dotenv
from pathlib import Path

from arg_parser import args, parser
from crypting import Encrypt, Decrypt, Encrypter, CryptographProcess


encrypter = Encrypter()
encrypt = Encrypt(encrypter)
#print(encrypt)
decrypt = Decrypt(encrypter)
process = CryptographProcess(encrypt)
#a = process.make_process(b"alladyn")
# print(a)
# process = CryptographProcess(decrypt)
# b = process.make_process(a)
# print(b.decode('utf-8'))
#file_pth = Path("enter path")
#print(encrypter.encrypt_file(file_pth))
# file_pth = Path("test.txt.enc")
#print(encrypter.decrypt_file(file_pth))

# encrypter.encrypt_folder("for_test")
folder_path = Path("for_test")
#encrypter.encrypt_folder(folder_path)
#encrypter.decrypt_folder(folder_path)

def main():
    encrypter = Encrypter()

    if args.mode == "encrypt":
        if args.file:
            encrypter.encrypt_file(Path(args.file))
        elif args.dir:
            encrypter.encrypt_folder(Path(args.dir))
        elif args.message:
            print(encrypter.encrypt_message(args.message))
    elif args.mode == "decrypt":
        if args.file:
            encrypter.decrypt_file(Path(args.file))
        elif args.dir:
            encrypter.decrypt_folder(Path(args.dir))
        elif args.message:
            print(encrypter.decrypt_message(args.message))

# TODO: check in encrypt_file if given path is a file (use os.path.isdir())
#TODO: remove returning bytes after encryption, give result in string(add
#       return process.make_process(text.encode("utf-8")).decode("utf-8") to encrypt_message) - check inf other methods
# ToDo: add verbose in arg parse
# ToDo: integrate program with console arguments(argparse)
# ToDo: Add procedure to en/decrypt many files or folders
# ToDo: add destination path as option to encryption process (en/decrypt folder, files to another location)
# ToDo: 
# ToDo: print done after finish script
# ToDo: print encryption process time (with progress bar maybe)
# ToDo: add encryption process to another thread
# # ToDo make exception handling for KeyboardInterrupt

if __name__ == "__main__":
    main()
