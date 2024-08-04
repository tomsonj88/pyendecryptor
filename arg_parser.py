import argparse

import crypting

parser = argparse.ArgumentParser(prog="Pyendecryptor",
                                 description="Program for encrypt/decrypt "
                                             "message, file or directory"
                                 )

parser.add_argument("-m",
                    "--mode",
                    choices=["encrypt", "decrypt"],
                    default="encrypt",
                    help="Choose mode of operation: encrypt or decrypt"
                    )
data_group = parser.add_mutually_exclusive_group()
data_group.add_argument("-f",
                        "--file"
                        )
data_group.add_argument("-d",
                        "--dir",
                        help="Directory to encrypt/decrypt"
                        )
data_group.add_argument("-msg",
                        "--message"
                        )
parser.add_argument("-p",
                    "--password",
                    action='store_true',
                    help="Password for encryption/decryption"
                    )
parser.add_argument("-s",
                    "--salt",
                    action='store_true',
                    help="Salt for password"
                    )
parser.add_argument("-ko",
                    "--keep_originals",
                    help="Remove original file/folder after "
                         "encryption/decryption"
                    )
# parser.add_argument("-v",
#                     "--verbose",
#                     count=True,
#                     default=0,
#                     help="Verbose mode"
#                     )

args = parser.parse_args()
