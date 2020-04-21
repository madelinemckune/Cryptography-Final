# adapted from inmcm's present code
# set for 128bit keys, can be easily switched to 80bit

# to read in from input.txt, first line is the current round key
# second line is the round state
from __future__ import print_function
from binascii import hexlify

s_box = (0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
         0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2)

inv_s_box = (0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD,
             0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA)

p_layer_order = [0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51, 4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38,
                 54, 7, 23, 39, 55, 8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59, 12, 28, 44, 60, 13,
                 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63]

block_size = 64

ROUND_LIMIT = 32

# performs round function


def round_function(state, key):
    new_state = state ^ key
    state_nibs = []
    for x in range(0, block_size, 4):
        nib = (new_state >> x) & 0xF
        sb_nib = s_box[nib]
        state_nibs.append(sb_nib)

    state_bits = []
    for y in state_nibs:
        nib_bits = [1 if t == '1'else 0 for t in format(y, '04b')[::-1]]
        state_bits += nib_bits

    state_p_layer = [0 for _ in range(64)]
    for p_index, std_bits in enumerate(state_bits):
        state_p_layer[p_layer_order[p_index]] = std_bits

    round_output = 0
    for index, ind_bit in enumerate(state_p_layer):
        round_output += (ind_bit << index)

    return round_output

# performs the key update function (80)


def key_function_80(key, round_count):

    r = [1 if t == '1'else 0 for t in format(key, '080b')[::-1]]

    h = r[-61:] + r[:-61]

    round_key_int = 0
    for index, ind_bit in enumerate(h):
        round_key_int += (ind_bit << index)

    upper_nibble = round_key_int >> 76

    upper_nibble = s_box[upper_nibble]

    xor_portion = ((round_key_int >> 15) & 0x1F) ^ round_count

    round_key_int = (round_key_int & 0x0FFFFFFFFFFFFFF07FFF) + \
        (upper_nibble << 76) + (xor_portion << 15)

    return round_key_int

# performs key update (128 bit)


def key_function_128(key, round_count):
    r = [1 if t == '1'else 0 for t in format(key, '0128b')[::-1]]

    h = r[-61:] + r[:-61]

    round_key_int = 0
    for index, ind_bit in enumerate(h):
        round_key_int += (ind_bit << index)

    upper_nibble = (round_key_int >> 124) & 0xF
    second_nibble = (round_key_int >> 120) & 0xF

    upper_nibble = s_box[upper_nibble]
    second_nibble = s_box[second_nibble]

    xor_portion = ((round_key_int >> 62) & 0x1F) ^ round_count

    round_key_int = (round_key_int & 0x00FFFFFFFFFFFFF83FFFFFFFFFFFFFFF) + \
        (upper_nibble << 124) + (second_nibble << 120) + (xor_portion << 62)

    return round_key_int


key_schedule = []
file_name = "../to_enc.txt"
plaintext = ""
with open(file_name, 'r') as fo:
    plaintext = fo.read()
hextext = (hexlify(plaintext.encode()))
# 128bit
current_round_key = int(hextext, 16)
round_state = int("0x0000000000000000", 16)


# create key schedule - operating in 128bit
for rnd_cnt in range(ROUND_LIMIT):
    key_schedule.append(current_round_key >> 64)
    current_round_key = key_function_128(current_round_key, rnd_cnt + 1)

# if key is 80bit
# for rnd_cnt in range(ROUND_LIMIT):
#    key_schedule.append(current_round_key >> 16)
#    current_round_key = key_function_80(current_round_key,rnd_cnt + 1)


# creates round states
for rnd in range(ROUND_LIMIT - 1):
    round_state = round_function(round_state, key_schedule[rnd])

round_state ^= key_schedule[31]
print(hex(round_state))
# 128bit test is 0x96db702a2e6900af
