# Got from https://github.com/devaar100/GrainCipher/blob/master/Grain%20Cipher.ipynb

import numpy as np
import binascii

import random
import string

# Hepler functions for interconversion of bits and strings


def string2bits(s=''):
    return [bin(ord(x))[2:].zfill(8) for x in s]


def text_to_bits(text, encoding='utf-8', errors='surrogatepass'):
    bits = bin(int(binascii.hexlify(text.encode(encoding, errors)), 16))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))


def text_from_bits(bits, encoding='utf-8', errors='surrogatepass'):
    n = int(bits, 2)
    return int2bytes(n).decode(encoding, errors)


def int2bytes(i):
    hex_string = '%x' % i
    n = len(hex_string)
    return binascii.unhexlify(hex_string.zfill(n + (n & 1)))


# Initialise LFSR and NFSR using IV and Secret Key
# First load the NFSR with the key bits, bi = ki, 0 ≤ i ≤ 79,
# then load the first 64 bits of the LFSR with the IV, si = IVi, 0 ≤ i ≤ 63.
# The remaining bits of the LFSR are filled with ones, si = 1, 64 ≤ i ≤ 79.
# Because of this the LFSR cannot be initialized to the all zero state.

def init(iv, key):
    iv_bin = string2bits(iv)
    iv_bin = ''.join(iv_bin)
    lfsr[:64] = [bool(int(iv_bin[ix])) for ix in range(len(iv_bin))]
    lfsr[64:] = 1
    key_bin = string2bits(key)
    key_bin = ''.join(key_bin)
    nfsr[:] = [bool(int(key_bin[ix])) for ix in range(len(key_bin))]

# The cipher is clocked 160 times without producing any running key
# The output of the filter function, h(x), is fed back and xored with the input, both to the LFSR and to the NFSR


def clock():
    hx = 0
    fx = 0
    gx = 0
    global lfsr
    global nfsr
    for ix in range(160):
        fx = lfsr[62] ^ lfsr[51] ^ lfsr[38] ^ lfsr[23] ^ lfsr[13] ^ lfsr[0] ^ hx
        gx = hx ^ nfsr[0] ^ nfsr[63] ^ nfsr[60] ^ nfsr[52] ^ nfsr[45] ^ nfsr[37] ^ nfsr[33] ^ nfsr[28] ^ nfsr[21] ^ nfsr[15] ^ nfsr[19] ^ nfsr[0] ^ nfsr[63] & nfsr[60] ^ nfsr[37] & nfsr[33] ^ nfsr[15] & nfsr[9] ^ nfsr[60] & nfsr[52] & nfsr[45] ^ nfsr[33] & nfsr[28] & nfsr[21] ^ nfsr[63] & nfsr[
            45] & nfsr[28] & nfsr[9] ^ nfsr[60] & nfsr[52] & nfsr[37] & nfsr[33] ^ nfsr[63] & nfsr[60] & nfsr[21] & nfsr[15] ^ nfsr[63] & nfsr[60] & nfsr[52] & nfsr[45] & nfsr[37] ^ nfsr[33] & nfsr[28] & nfsr[21] & nfsr[15] & nfsr[9] ^ nfsr[52] & nfsr[45] & nfsr[37] & nfsr[33] & nfsr[28] & nfsr[21]
        x0 = lfsr[0]
        x1 = lfsr[25]
        x2 = lfsr[46]
        x3 = lfsr[64]
        x4 = nfsr[63]
        hx = x1 ^ x4 ^ x0 & x3 ^ x2 & x3 ^ x3 & x3 ^ x0 & x1 & x2 ^ x0 & x2 & x3 ^ x0 & x2 & x4 ^ x1 & x2 & x4 ^ x2 & x3 & x4
        lfsr[:-1] = lfsr[1:]
        lfsr[-1] = fx
        nfsr[:-1] = nfsr[1:]
        nfsr[-1] = gx

# Return a stream generator which implements the filter function


def gen_key_stream():
    hx = 0
    while True:
        fx = lfsr[62] ^ lfsr[51] ^ lfsr[38] ^ lfsr[23] ^ lfsr[13] ^ lfsr[0]
        gx = nfsr[0] ^ nfsr[63] ^ nfsr[60] ^ nfsr[52] ^ nfsr[45] ^ nfsr[37] ^ nfsr[33] ^ nfsr[28] ^ nfsr[21] ^ nfsr[15] ^ nfsr[19] ^ nfsr[0] ^ nfsr[63] & nfsr[60] ^ nfsr[37] & nfsr[33] ^ nfsr[15] & nfsr[9] ^ nfsr[60] & nfsr[52] & nfsr[45] ^ nfsr[33] & nfsr[28] & nfsr[21] ^ nfsr[63] & nfsr[
            45] & nfsr[28] & nfsr[9] ^ nfsr[60] & nfsr[52] & nfsr[37] & nfsr[33] ^ nfsr[63] & nfsr[60] & nfsr[21] & nfsr[15] ^ nfsr[63] & nfsr[60] & nfsr[52] & nfsr[45] & nfsr[37] ^ nfsr[33] & nfsr[28] & nfsr[21] & nfsr[15] & nfsr[9] ^ nfsr[52] & nfsr[45] & nfsr[37] & nfsr[33] & nfsr[28] & nfsr[21]
        x0 = lfsr[0]
        x1 = lfsr[25]
        x2 = lfsr[46]
        x3 = lfsr[64]
        x4 = nfsr[63]
        hx = x1 ^ x4 ^ x0 & x3 ^ x2 & x3 ^ x3 & x3 ^ x0 & x1 & x2 ^ x0 & x2 & x3 ^ x0 & x2 & x4 ^ x1 & x2 & x4 ^ x2 & x3 & x4
        lfsr[:-1] = lfsr[1:]
        lfsr[-1] = fx
        nfsr[:-1] = nfsr[1:]
        nfsr[-1] = gx
        yield hx


def encrypt(iv, key, plain):
    init(iv, key)
    clock()
    plain = text_to_bits(plain)
    stream = gen_key_stream()
    cipher = [str(int(bool(int(plain[ix])) ^ next(stream)))
              for ix in range(len(plain))]
    cipher = ''.join(cipher)
    return cipher


def decrypt(iv, key, cipher):
    init(iv, key)
    clock()
    stream = gen_key_stream()
    plain = [str(int(bool(int(cipher[ix])) ^ next(stream)))
             for ix in range(len(cipher))]
    plain = ''.join(plain)
    plain = text_from_bits(plain)
    return plain

# Got from Pynative example


def randomString(stringLength=8):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))


def encrypt_file(file_name, iv, key):
    with open(file_name, 'r') as fo:
        plaintext = fo.read()
    enc = encrypt(iv, key, plaintext)
    with open(file_name + ".enc", 'w') as fo:
        fo.write(enc)


def decrypt_file(file_name, iv, key):
    with open(file_name, 'r') as fo:
        ciphertext = fo.read()
    dec = decrypt(iv, key, ciphertext)
    with open(file_name[:-4], 'w') as fo:
        fo.write(dec)
# Main building blocks of Grain Cipher, namely a Linear Feedback Shift Register (LFSR)
# and a Non-linear Feedback Shift Register (NFSR)


lfsr = np.zeros(80, dtype=bool)
nfsr = np.zeros(80, dtype=bool)
iv = 'abababab'
key = 'bababababa'
init(iv, key)


# Read in data from file and encrypt to file

fileName = "../to_enc.txt"
encrypt_file(fileName, iv, key)
