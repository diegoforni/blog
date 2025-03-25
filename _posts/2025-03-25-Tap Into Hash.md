---
title: PicoCTF Tap Into Hash Writeup
author: Diego Forni
date: 2025-03-24 14:10:00 +0800
categories: [CTF]
tags: [CTF, Writeup, Reverse Engineering, PicoCTF]
render_with_liquid: false
---

Here you will see my detailed approach to the Challenge Tap into Hash from PicoCTF. This is not meant to be the perfect solution, just how I thought through this problem.

## Understanding the problem
The first step is to identify what useful information we have:
1. Source code
   * A Python file with a custom data structure for a blockchain, alongside many algorithms including encryption for this blockchain.
2. Encrypted Flag
   * Contains Key and Encrypted Blockchain

I will first focus on the source code.

## Source code analysis
As this code is quite extensive, I will not detail the whole analysis; however, you should do it. 
We will focus on the function `encrypt`.

```python
def encrypt(plaintext, inner_txt, key):
    midpoint = len(plaintext) // 2

    first_part = plaintext[:midpoint]
    second_part = plaintext[midpoint:]
    modified_plaintext = first_part + inner_txt + second_part
    block_size = 16
    plaintext = pad(modified_plaintext, block_size)
    key_hash = hashlib.sha256(key).digest()

    ciphertext = b''

    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        cipher_block = xor_bytes(block, key_hash)
        ciphertext += cipher_block

    return ciphertext
```

This function is called in main as `encrypted_blockchain = encrypt(blockchain_string, token, key)` where `blockchain_string` represents the concatenation of the hashes of each block, `token` is the argument the user enters in the execution of the program, and `key` is randomly generated.

What is happening when we call `encrypt`? First, the token is inserted in the middle of `blockchain_string`, and then the function `pad` adds some bytes to make the length of plaintext divisible by 16, the block size.

So now, plaintext contains the first half of the `blockchain_string`, the user token, the second half of `blockchain_string`, and some padding to make it divisible in blocks of 16 bytes.

The next loop is the main part of this CTF. We can see that it iterates over plaintext, block by block, performing an `xor` between the block and the key hash. If we find a way to reverse this operation, we will find the flag.

So, what is the inverse function of `xor`? The answer is `xor`. Here is an example:

Given three variables:  

- a
- b
- c = a ⊕ b

To retrieve `a`, XOR `c` with `b`:  

a = c ⊕ b

Concluding, we already have an algorithm to reverse the encryption. It's the same function, but with different parameters.

## Encrypted Flag
In the file we have:

``` 
Key: b"\x1br\t;\x0f\xb5\x9f\xaa\xd1'\xaf\x86[\xf0\xe6\xd9'D\xf9\x8d\x17g\xeb>_gG.\xd4\xc3\xdc\x83"
Encrypted Blockchain: b'o\x14>\xda\x16\xc7\xce\xd784,.\x8f2\x80@cD?\xd3L\x90\x9f\x87l0yy\xdam\x85J1\x139\x88\x10\x95\x9f\x82ke*.\xda>\xd3\x195O?\xd3\x10\xc4\x94\x83kd| \x882\x86IzFk\xd2@\x95\xcd\x83:by{\x8c3\x81\x1e6E8\xdaC\xc2\xcf\xd087||\x8em\xd0\x1c3Cj\xde\x10\xc0\x99\x89;4+{\x8fn\x84\x1abN9\xdc\x16\xc5\xc8\xd0mc}+\x81o\xd7J1[k\xda\x12\x94\xce\x89m3}(\xdbh\x84KeDh\x8fF\x9e\xc9\x84i1.*\x8f2\x87\x1d4\x15+\x83\x17\xc9\xef\xe5Iz*t\xd7h\xd9\'d%\t\x82"\xcf\xfe\xd3[09{\xe0T\xea-=;k\x98@\x9f\xcf\xf9Pp\x0bb\xd5A\xe8\x02\x15=\x04\x8eL\x96\x9f\x86n0ze\x89m\x81A6Bi\x88B\x91\xce\x8279q~\x8d:\x84OfAn\x8fA\x95\xc9\xd76d|}\x95;\x82@oFb\xddE\x93\x98\xd2jdz/\x88h\xd7\x1a6@o\xdd\x12\x94\x94\xd2m`}y\x8c>\x82LaCm\x8f\x10\x9f\x9f\xd3>0py\xde2\x87AoGh\x88\x11\x91\x9a\x84=3z*\xde&\x82Hb@n\xddM\xc3\xce\x89me.(\x808\xd0KaGo\x8bG\x91\x9b\x81?`.|\xde=\xd6@b\x17m\x8e\x11\x9f\x95\x80>d+.\x88>\x80\x1d4\x14m\xdd\x12\x96\xcf\x85m1q-\x8ao\xb0z'
```

We now need to identify which parameters we know to feed into the `xor` to retrieve an unknown one.
``` python
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]
        cipher_block = xor_bytes(block, key_hash)
        # block = a, We do not have the block
        # key_hash = b, We do not have it
        # a xor b = c = ciphertext, It is given in encrypted blockchain
        # a = b xor c 
        ciphertext += cipher_block
```

We only have one of the 3 variables. We cannot yet perform the XOR to get the original blocks.
However, we do have the key, and the `key_hash` was obtained with SHA-256 and the key. As SHA-256 is deterministic, if we run it with the key in the file `enc_flag` we get:
```
key_hash = b'Wv[\xeat\xa6\xac\xb1\x0f\x01H\x18\xb8\x0b\xb2x-\x99\xdf\xcc\x1f`\x90N\nTP/\x1a\x92\xb0w'
```

So, we now have 2 of the 3 variables: the `cipher_block`, which is a block of 16 extracted from Encrypted Blockchain in `enc_flag`, and the `key_hash`. We can perform an XOR and get the original blocks:

``` python
encBlock = b'o\x14>\xda\x16\xc7\xce\xd784,.\x8f2\x80@cD?\xd3L\x90\x9f\x87l0yy\xdam\x85J1\x139\x88\x10\x95\x9f\x82ke*.\xda>\xd3\x195O?\xd3\x10\xc4\x94\x83kd| \x882\x86IzFk\xd2@\x95\xcd\x83:by{\x8c3\x81\x1e6E8\xdaC\xc2\xcf\xd087||\x8em\xd0\x1c3Cj\xde\x10\xc0\x99\x89;4+{\x8fn\x84\x1abN9\xdc\x16\xc5\xc8\xd0mc}+\x81o\xd7J1[k\xda\x12\x94\xce\x89m3}(\xdbh\x84KeDh\x8fF\x9e\xc9\x84i1.*\x8f2\x87\x1d4\x15+\x83\x17\xc9\xef\xe5Iz*t\xd7h\xd9\'d%\t\x82"\xcf\xfe\xd3[09{\xe0T\xea-=;k\x98@\x9f\xcf\xf9Pp\x0bb\xd5A\xe8\x02\x15=\x04\x8eL\x96\x9f\x86n0ze\x89m\x81A6Bi\x88B\x91\xce\x8279q~\x8d:\x84OfAn\x8fA\x95\xc9\xd76d|}\x95;\x82@oFb\xddE\x93\x98\xd2jdz/\x88h\xd7\x1a6@o\xdd\x12\x94\x94\xd2m`}y\x8c>\x82LaCm\x8f\x10\x9f\x9f\xd3>0py\xde2\x87AoGh\x88\x11\x91\x9a\x84=3z*\xde&\x82Hb@n\xddM\xc3\xce\x89me.(\x808\xd0KaGo\x8bG\x91\x9b\x81?`.|\xde=\xd6@b\x17m\x8e\x11\x9f\x95\x80>d+.\x88>\x80\x1d4\x14m\xdd\x12\x96\xcf\x85m1q-\x8ao\xb0z'
key_hash = b'Wv[\xeat\xa6\xac\xb1\x0f\x01H\x18\xb8\x0b\xb2x-\x99\xdf\xcc\x1f`\x90N\nTP/\x1a\x92\xb0w'

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

ciphertext = b''

for i in range(0, len(encBlock), 16):
    block = encBlock[i:i + 16]
    cipher_block = xor_bytes(block, key_hash)
    ciphertext += cipher_block

print(ciphertext)
# print result: b'8be0babf75d6792842d98636c11abf72febbd333ddb6b5aab9d9db82de480941-00843a25c1c483fa3c07dca764d6fbdd514df5845cc7e6b58b6bcdabb539de2f-00f2b8b250cc63223e28e5f0f2795eccpicoCTF{block_3SRhViRbT1qcX_XUjM0r49cH_qCzmJZzBK_d8037a12}1f39a42b67b3889f5167175e53ef9e4e-0088097154cee270ceba647f28cba5a4504656ed93b118af959813be7652222f-0056579eb8bdf083b3614a37700afdf6d85a6de9911ec6052ecb67f0c4b0952d\x02\x02'
```

And in the middle of the concatenation of hashes, we can see the flag:
`picoCTF{block_3SRhViRbT1qcX_XUjM0r49cH_qCzmJZzBK_d8037a12}`