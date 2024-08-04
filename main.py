import argparse
import os

from dotenv import load_dotenv

from pathlib import Path
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
encrypter.decrypt_folder(folder_path)

