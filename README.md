# file-encrypter-decrypter

## Encryption algorithms

This program uses two basic encryption algorithms:

* _Algorithm A_: The bytes corresponding to the ASCII character are replaced by their 2's complement. Then, the resulting binary string is shifted to the left by __C__, where C is a user-inputted integer that can range from 0 to 7.
* _Algorithm B_: The file is processed in blocks of 10 bytes. Ones' complement is applied to each block, then the block is *XOR*ed with a 64-bit encryption key, which is user-inputted.
