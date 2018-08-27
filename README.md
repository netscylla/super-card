# Super-exe
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fnetscylla%2Fsuper-card.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fnetscylla%2Fsuper-card?ref=badge_shield)

An interface to the Mifare Super (Suppa/Supper) Card utilising the libnfc 1.7.1 library.
Many super-card card programs are either broken / wrong type / or written in Chinese.
This is a simple English (American) Language program to faciliate non-Chinese users.

This program has been tested successfully on the USB ACR-122U reader on the following operating systems:
* WinXP (32bit) SP0/1/2/3
* Vista  (32bit) SP0/1/2

**Note**: From Windows 7+ Microsoft changed the way smartcard drivers operate, and I havnt figured out how to support the later versions of Windows.

The program has two modes read & write, these operations are detailed below...

# Usage
## Set a UID
Using the '-w' flag set a 4-byte (8 hex chars) UID
```
$ nfc-super.exe -w 22334455
Mifare Super Card v0.1 (C)2014 Andy
ISO/IEC 14443A (106 kbps) target:
    ATQA (SENS_RES): 00  04
       UID (NFCID1): 11  22  33  44
      SAK (SEL_RES): 08
```
## Operation
Place the card upto a Mifare reader, and ensure you obtain two or more (2+) failed authentication attempts.

## Obtain data and crack key
Place the super-card on the reader, launch the program with the '-r' flag, the program should automatically
obtain the necessary values and crack the reader key. 
```
$ nfc-super.exe -r
Mifare Super Card v0.1 (C)2014 Andy
ISO/IEC 14443A (106 kbps) target:
    ATQA (SENS_RES): 00  04
       UID (NFCID1): 22  33  44  55
      SAK (SEL_RES): 08
 UID: 22  33  44  55
1:NR: c9  6f  2e  a5
1:AR: 71  67  3d  4d
2:NR: 38  aa  fa  ba
2:AR: 5d  32  cd  f4
Cracking...
Found Key: [e5b20aeeffff]
```

# Further cracking
Use the Mifare nested attack (or mfoc.exe) to crack any remaining keys on a genuine card.

## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fnetscylla%2Fsuper-card.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fnetscylla%2Fsuper-card?ref=badge_large)