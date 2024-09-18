#!/usr/bin/python3
import hashlib, time, argparse
from colorama import Fore
from colorama import init
from threading import Thread

# Initialize colorama
init(autoreset=True)

# Banner text
banner_t = """
            +++++++++++++++++++++++++++++++++++++++++++++++++++++
            #    Hash Cracker - Md5 , Sha1 , Sha224 ,           #
            #                 Sha256 , Sha384 , Sha512          #
            #    Version 2.0                                    #
            #    Github : https://github.com/N4tzz-Official     #
            #    Email : N4tzzOfficial@proton.me                #
            #    Code By : Owner N4tzzSquad                     #
            #                                                   #
            #    N4tzzSquad Team                                #
            +++++++++++++++++++++++++++++++++++++++++++++++++++++
    """

# Display banner
def banner(txt):
    for x in txt:
        print(Fore.LIGHTYELLOW_EX + x, end='', flush=True)
        time.sleep(0.0003)
    print()

# Argument parsing
def a_parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-w', dest='WORDLIST', help='WordList')
    parser.add_argument('-f', dest='HASHLIST', help='Hash List')
    parser.add_argument('-H', dest='HASH', help='One Hash For Crack')
    parser.add_argument('-c', dest='COMBO', help='Combo For Crack')
    parser.add_argument('-t', dest='TYPE', help='Type Hash (md5, sha1, sha256, sha512)')
    return parser.parse_args()

# Hash cracking functions
def md5_crack(password, hash):
    try:
        res = hashlib.md5(password.strip().encode('utf-8')).hexdigest()
        if ":" in hash and res == hash.split(":")[1]:
            print(Fore.GREEN + hash.split(":")[0] + ":" + Fore.LIGHTGREEN_EX + password)
        elif res == hash:
            print(Fore.LIGHTGREEN_EX + password + ":" + Fore.GREEN + hash)
    except KeyboardInterrupt:
        print(Fore.RED + "Error. Cancelled")

def sha1_crack(password, hash):
    try:
        res = hashlib.sha1(password.strip().encode('utf-8')).hexdigest()
        if ":" in hash and res == hash.split(":")[1]:
            print(Fore.GREEN + hash.split(":")[0] + ":" + Fore.LIGHTGREEN_EX + password)
        elif res == hash:
            print(Fore.LIGHTGREEN_EX + password + ":" + Fore.GREEN + hash)
    except KeyboardInterrupt:
        print(Fore.RED + "Error. Cancelled")

# Similar functions for sha224, sha256, sha384, sha512 (omitted for brevity)
# ... (Add sha224_crack, sha256_crack, sha384_crack, sha512_crack)

# Cracking functions
def file_crack(hashpath, wordpath, fun_type):
    try:
        banner(banner_t)
        with open(hashpath, "r", encoding='utf-8') as hash_file:
            hashes = hash_file.readlines()
        with open(wordpath, "r", encoding='utf-8') as password_file:
            passwords = password_file.readlines()
        for h in hashes:
            for pa in passwords:
                t = Thread(target=fun_type, args=(pa.strip(), h.strip()))
                t.start()
                t.join()  # Ensure all threads complete before exiting
    except KeyboardInterrupt:
        print(Fore.RED + "Error. Cancelled")

def combo_crack(combo, wordpath, fun_type):
    try:
        banner(banner_t)
        with open(combo, "r", encoding='utf-8') as combo_file:
            combos = combo_file.readlines()
        with open(wordpath, "r", encoding='utf-8') as password_file:
            passwords = password_file.readlines()
        for c in combos:
            for pa in passwords:
                t = Thread(target=fun_type, args=(pa.strip(), c.strip()))
                t.start()
                t.join()
    except KeyboardInterrupt:
        print(Fore.RED + "Error. Cancelled")

def one_crack(hash, wordpath, fun_type):
    try:
        banner(banner_t)
        with open(wordpath, "r") as password_file:
            passwords = password_file.readlines()
        for pa in passwords:
            t = Thread(target=fun_type, args=(pa.strip(), hash))
            t.start()
            t.join()
    except KeyboardInterrupt:
        print(Fore.RED + "Error. Cancelled")

# Main logic
if __name__ == '__main__':
    args = a_parse()
    if args.HASH and args.WORDLIST:
        if args.TYPE == 'md5':
            one_crack(args.HASH, args.WORDLIST, md5_crack)
        elif args.TYPE == 'sha1':
            one_crack(args.HASH, args.WORDLIST, sha1_crack)
        # Add more cases for sha224, sha256, etc.
    elif args.HASHLIST and args.WORDLIST:
        if args.TYPE == 'md5':
            file_crack(args.HASHLIST, args.WORDLIST, md5_crack)
        elif args.TYPE == 'sha1':
            file_crack(args.HASHLIST, args.WORDLIST, sha1_crack)
        # Add more cases for sha224, sha256, etc.
    elif args.COMBO and args.WORDLIST:
        if args.TYPE == 'md5':
            combo_crack(args.COMBO, args.WORDLIST, md5_crack)
        elif args.TYPE == 'sha1':
            combo_crack(args.COMBO, args.WORDLIST, sha1_crack)
        # Add more cases for sha224, sha256, etc.
