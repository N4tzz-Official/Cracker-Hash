Hash-Cracker
A tool for cracking different hashes . The hashes that the tool supports are (MD5 , Sha1 , Sha224 , Sha256 , Sha384 , Sha512) . The tool can retrieve a hash or a file hash or a combo list and cracking all on the wordlist . coded by N4tzzSquad
Installation & Runing
$ cd Hash-Cracker 
$ pip3 install -r requirements.txt
$ python3 hash-cracke.py -h 
$ python3 hash-cracke.py -H [hash] -w /root/Desktop/passlist.txt -t md5
$ python3 hash-cracke.py -f /root/Desktop/hashfile.txt -w /root/Desktop/passlist.txt -t md5
$ python3 hash-cracke.py -c /root/Desktop/combo.txt -w /root/Desktop/passlist.txt -t md5
Guide
Description of tool options

-h Help
-H Hash Text
-f Hash File
-c Combo List
-w Wordlist Path
-t Hash Type {md5 , sha1 ,sha224 , sha256 , Sha384 , sha512}

"PLEASE DO NOT COPY OR COPYRIGHT ALL SATA CODES AND OTHERS IF YOU WANT TO COPY / COPYRIGHT PLEASE EMAIL PERMISSION: N4tzzOfficial@proton.me"
:smile
