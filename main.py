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

def print_verbose(message: str):
    if args.verbose:
        print(message)

def main():
    encrypter = Encrypter()

    if args.mode == "encrypt":
        if args.file:
            # encrypter.encrypt_file(Path(args.file))
            encrypter.encrypt_files(args.file, args.dest_path)
        elif args.dir:
            encrypter.encrypt_folders(args.dir, args.dest_path)
        elif args.message:
            print(encrypter.encrypt_message(args.message))
    elif args.mode == "decrypt":
        if args.file:
            encrypter.decrypt_files(args.file, args.dest_path)
        elif args.dir:
            encrypter.decrypt_folders(args.dir, args.dest_path)
        elif args.message:
            print(encrypter.decrypt_message(args.message))
    print("Script execution done")

    # encrypter.encrypt_folder(folder_path=Path(r".\for_test\spr"),
    #                        destination_path=Path(r".\for_test\dec"))
    # encrypter.decrypt_folder(folder_path=Path(r".\for_test\dec"),
    #                        destination_path=Path(r".\for_test\spr"))
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Operation interrupted by user")
