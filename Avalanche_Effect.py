import random
import string

sbox = [
        [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
        [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
        [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
        [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
        [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
        [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
        [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
        [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
        [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
        [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
        [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
        [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
        [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
        [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
        [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
        [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
]

r_con = ["0000000000000001", "0000000000000010", "0000000000000100", "0000000000001000", "0000000000010000", "0000000000100000", "0000000001000000", "0000000010000000", "0000000000011011", "0000000000110110"]

fixed = ["0000000000000010", "0000000000000011", "0000000000000001", "0000000000000001", "0000000000000001", "0000000000000010", "0000000000000011", "0000000000000001", "0000000000000001", "0000000000000001", "0000000000000010", "0000000000000011",  "0000000000000011", "0000000000000001", "0000000000000001", "0000000000000010", ]

"""
This function generates an initial vector that is going to be used in the CBC mode of AES-128
The initial vector is returned as a list containing lists. Each list is one byte. 
Notice that we work we hex numbers, so the first 8 bits of each of the 16 bytes are always 0.
"""
def generate_initial_vector():
    vector = []
    for i in range(0, 16):
        num = "0" * 8
        for j in range(0, 8):
            random_num = random.choice([0,1])
            if random_num == 1:
                num += "1"
            else:
                num += "0"
        hex_num = hex(int(num, 2))
        vector.append(hex_num)
    return vector

"""
This function converts a hex string to text
"""
def convert_hex_to_text(hex_data):
    ascii_string = ''
    for i in hex_data:
        txt = i[2:]
        # print(txt)
        if len(txt) == 1:
            txt = bytes.fromhex("0" + txt).decode("ascii")
            ascii_string = ascii_string + txt
        else:
            ascii_string = ascii_string + bytes.fromhex(i[2:]).decode("ascii")
    # print("ASCII string: ", ascii_string)
    return ascii_string

"""
This function changes randomly one bit in the message passed as a parameter.
"""
def random_bit_change(message):
    hex_message = convert_string_list_to_hex(message)
    binary_number = []
    for i in hex_message:
        binary_number.append(convert_hex_to_binary(i))
    random_bit_group = random.randint(0, 31)
    bit_to_change = random.randint(1, 7)
    if binary_number[random_bit_group][-bit_to_change] == "0":
        num_list = list(binary_number[random_bit_group])
        num_list[-bit_to_change] = "1"
        binary_number[random_bit_group] = "".join(num_list)
    elif binary_number[random_bit_group][-bit_to_change] == "1":
        num_list = list(binary_number[random_bit_group])
        num_list[-bit_to_change] = "0"
        binary_number[random_bit_group] = "".join(num_list)
    hex_message = []
    for i in range(0, 32):
        hex_message.append(hex(int(binary_number[i], 2)))
    return hex_message

"""
This function generates randomly a 16 byte string message where each character is 1 byte = 8 bits
"""
def generate_message(length):
    return "".join(random.choice(string.ascii_letters) for x in range(length))

def convert_string_list_to_hex(sentence):
    sentence_hex = []
    for letter in sentence:
        sentence_hex.append("0x" + letter.encode("ascii").hex())
    return sentence_hex

"""
This function performs the xor logic operation between the bits of two messages
"""
def xor(first_number, second_number):
    result = ""
    for bit in range(0, len(first_number)):
        if first_number[bit] == second_number[bit]:
            result += "0"
        else:
            result += "1"
    return result

"""
This function calculates the result of g(w[i]) in AES-128
"""
def calculate_g(w, loop):
    w = w[1:] + w[:1]
    # Byte substitution
    for i in range(0, 4):
        w[i] = byte_substitution_from_sbox(w[i], i, loop)
    return w


def convert_hex_to_binary(hex_number):
    # print(hex_number)
    binary = str(bin(int(hex_number, 16))[2:].zfill(len(hex_number) * 4))
    if len(binary) < 16:
        missing_zeros = 16 - len(binary)
        zeros = ""
        for i in range(0, missing_zeros):
            zeros += "0"
        binary = zeros + binary
    return binary

def convert_binary_to_decimal(num):
    number = num[::-1]
    power = 0
    summary = 0
    for bit in number:
        summary += (2 ** power) * int(bit)
        power += 1
    return str(summary)

"""
This function performs the substitution (S-box) in AES-128
"""
def byte_substitution_from_sbox(number_in_hex, position, loop):
    binary = convert_hex_to_binary(number_in_hex)
    high_nibble = binary[8:12]
    low_nibble = binary[12:16]
    high_nibble_decimal = convert_binary_to_decimal(high_nibble)
    low_nibble_decimal = convert_binary_to_decimal(low_nibble)
    substitution = sbox[int(high_nibble_decimal)][int(low_nibble_decimal)]
    substitution = hex(substitution)
    if position == 0:
        substitution_binary = convert_hex_to_binary(substitution)
        round_key = r_con[loop]
        substitution = hex(int(convert_binary_to_decimal(xor(substitution_binary, round_key))))
    return substitution

"""
This function calculates and returns the 10 round-keys of AES-128
"""
def get_round_keys(initial_key):
    round_keys = []
    w = [[0] * 4 for i in range(0, 44)]
    # Initializing first 4-blocks
    index = 0
    for i in range(0, 4):
        for j in range(0, 4):
            w[i][j] = initial_key[index]
            index += 1
    # Calculate the next 40 blocks
    i = 0
    j = 3
    k = 4
    loop = 0
    while k < 44:
        if k % 4 == 0:
            g_wj = calculate_g(w[j], loop)
            for hex_byte in range(0, 4):
                wi_binary = convert_hex_to_binary(w[i][hex_byte])
                wj_binary_byte = convert_hex_to_binary(g_wj[hex_byte])
                w[k][hex_byte] = hex(int(xor(wi_binary, wj_binary_byte), 2))
            loop += 1
        else:
            for hex_byte in range(0, 4):
                wi_binary = convert_hex_to_binary(w[i][hex_byte])
                wj_binary = convert_hex_to_binary(w[j][hex_byte])
                w[k][hex_byte] = hex(int(xor(wi_binary, wj_binary), 2))
        i += 1
        j += 1
        k += 1

    round_key = []
    for i in range(0, len(w)):
        for j in range(0, len(w[i])):
            round_key.append(w[i][j])
        if len(round_key) == 16:
            round_keys.append(round_key)
            round_key = []

    return round_keys

"""
This function performs the add round key part of AES-128
"""
def add_round_key(state_matrix, round_key_matrix):
    binary_xor = []
    for i in range(0, len(state_matrix)):
        binary_xor.append(xor(convert_hex_to_binary(state_matrix[i]), convert_hex_to_binary(round_key_matrix[i])))
    for i in range(0, len(binary_xor)):
        binary_xor[i] = hex(int(binary_xor[i], 2))
    return binary_xor

def substitute_entries(state_matrix):
    new_state = []
    for i in range(0, len(state_matrix)):
        new_state.append(byte_substitution_from_sbox(state_matrix[i], -1, -1))
    return new_state

def shift_rows(state_matrix):
    first_row = state_matrix[0:16:4]
    second_row = state_matrix[1:16:4]
    third_row = state_matrix[2:16:4]
    fourth_row = state_matrix[3:16:4]
    second_row = second_row[1:] + second_row[:1]
    third_row = third_row[2:] + third_row[:2]
    fourth_row = fourth_row[3:] + fourth_row[:3]
    new_state = first_row[0:4] + second_row[0:4] + third_row[0:4] + fourth_row[0:4]
    return new_state

"""
Multiplication in Galois field GF(2^8).
"""
def galois_multiply(x, y):
    product = 0
    for i in range(0, 8):
        if (y & 1) == 1:
            product ^= x
        hi_bit = x & 0x80
        x = (x << 1) & 0xFF
        if hi_bit == 0x80:
            x ^= 0x1B
        y >>= 1
    return product

"""
Mix column step of AES-128
"""
def mix_column(state_matrix, fixed_matrix):
    galois_results = []
    for k in range(0, 4):
        fixed_row = fixed_matrix[4*k:4*k+4]
        for i in range(0, 4):
            multiplication_results = []
            column = state_matrix[i:16:4]
            for j in range(0, 4):
                result = galois_multiply(int(hex(int(fixed_row[j], 2)), 16), int(column[j], 16))
                result = bin(result)
                result = result[2:]
                if len(result) < 8:
                    result = "0" * (8 - len(result)) + result
                multiplication_results.append(result)
            binary = xor(xor(xor(multiplication_results[0], multiplication_results[1]), multiplication_results[2]), multiplication_results[3])
            galois_results.append(hex(int(binary, 2)))
    return galois_results[0:16:4] + galois_results[1:16:4] + galois_results[2:16:4] + galois_results[3:16:4]


def AES_EBC(original_message_hex, key_hex):
    # Step 1: Find all 11 round keys
    all_round_keys = get_round_keys(key_hex)

    # Step 2: Round 0 -- Add round key
    new_state_matrix = add_round_key(original_message_hex, all_round_keys[0])

    # Step 3: Calculate the rounds 1 - 9
    for round_number in range(1, 10):
        # Substitute the entries
        new_state_matrix = substitute_entries(new_state_matrix)
        # Shift rows
        new_state_matrix = shift_rows(new_state_matrix)
        # Mix Columns
        new_state_matrix = mix_column(new_state_matrix, fixed)
        # Add round key
        new_state_matrix = add_round_key(new_state_matrix, all_round_keys[round_number])

    # Step 4: Round 10 -- No Mix Columns
    new_state_matrix = substitute_entries(new_state_matrix)
    new_state_matrix = shift_rows(new_state_matrix)
    new_state_matrix = new_state_matrix[0:16:4] + new_state_matrix[1:16:4] + new_state_matrix[
                                                                             2:16:4] + new_state_matrix[3:16:4]
    new_state_matrix = add_round_key(new_state_matrix, all_round_keys[10])
    # print("Ciphertext is: ", new_state_matrix)
    return new_state_matrix


def AES_CBC(original_message_hex, key_hex, vector):
    # Step 1: Find all 11 round keys
    all_round_keys = get_round_keys(key_hex)

    # Step 2: Xor the original message with the initial vector
    for i in range(0, 16):
        original_message_hex[i] = hex(int(xor(convert_hex_to_binary(vector[i]), convert_hex_to_binary(original_message_hex[i])), 2))

    # Step 3: Round 0 -- Add round key
    new_state_matrix = add_round_key(original_message_hex, all_round_keys[0])

    # Step 4: Calculate the rounds 1 - 9
    for round_number in range(1, 10):
        # Substitute the entries
        new_state_matrix = substitute_entries(new_state_matrix)
        # Shift rows
        new_state_matrix = shift_rows(new_state_matrix)
        # Mix Columns
        new_state_matrix = mix_column(new_state_matrix, fixed)
        # Add round key
        new_state_matrix = add_round_key(new_state_matrix, all_round_keys[round_number])

    # Step 5: Round 10 -- No Mix Columns
    new_state_matrix = substitute_entries(new_state_matrix)
    new_state_matrix = shift_rows(new_state_matrix)
    new_state_matrix = new_state_matrix[0:16:4] + new_state_matrix[1:16:4] + new_state_matrix[
                                                                             2:16:4] + new_state_matrix[3:16:4]
    new_state_matrix = add_round_key(new_state_matrix, all_round_keys[10])
    # print("Ciphertext is: ", new_state_matrix)
    return new_state_matrix

def count_different_bits(message1, message2):
    different_bits = 0
    for i in range(0, len(message1)):
        message1_bit = convert_hex_to_binary(message1[i])
        message2_bit = convert_hex_to_binary(message2[i])
        for k in range(8, 16):
            if message1_bit[k] != message2_bit[k]:
                different_bits += 1
    return different_bits / 256



# -------- MAIN PROGRAM --------

count_ebc = 0
count_cbc = 0

# Testing the AES-128 EBC and CBC in 50 different messages
for test_case in range(0, 50):

    # Step 1: Generate 256-bit messages and 128-bit keys and the initial vector for the CBC mode
    original_message = generate_message(32)
    key = generate_message(16)
    initial_vector = generate_initial_vector()

    # Step 2: Break the message into two 128-bit blocks
    first_block = original_message[0:16]
    second_block = original_message[16:32]

    # Step 3: Convert the strings from text to hex
    first_block_hex = convert_string_list_to_hex(first_block)
    second_block_hex = convert_string_list_to_hex(second_block)
    initial_key_hex = convert_string_list_to_hex(key)

    # Step 4: Apply AES-128 EBC Mode and AES-128 CBC Mode to each block
    ciphertext_ebc = AES_EBC(first_block_hex, initial_key_hex) + AES_EBC(second_block_hex, initial_key_hex)
    ciphertext_cbc_first_block = AES_CBC(first_block_hex, initial_key_hex, initial_vector)
    ciphertext_cbc_second_block = AES_CBC(second_block_hex, initial_key_hex, ciphertext_cbc_first_block)
    ciphertext_cbc = ciphertext_cbc_first_block + ciphertext_cbc_second_block

    # Step 5: Print the message, the key and the ciphertext
    # print("AES-128 EBC for the original message")
    # print("Original Message:", original_message, "Key:", key, "Ciphertext:", ciphertext_ebc)
    # print("AES-128 CBC for the original message")
    # print("Original Message:", original_message, "Key:", key, "Ciphertext:", ciphertext_cbc)

    # Step 6: Change randomly one bit and perform the same calculations as before
    new_message = random_bit_change(original_message)
    first_block = new_message[0:16]
    second_block = new_message[16:32]
    initial_vector = generate_initial_vector()
    ciphertext_ebc_new = AES_EBC(first_block, initial_key_hex) + AES_EBC(second_block, initial_key_hex)
    ciphertext_cbc_first_block = AES_CBC(first_block, initial_key_hex, initial_vector)
    ciphertext_cbc_second_block = AES_CBC(second_block, initial_key_hex, ciphertext_cbc_first_block)
    ciphertext_cbc_new = ciphertext_cbc_first_block + ciphertext_cbc_second_block
    # print("AES-128 EBC for the changed message")
    # print("Changed Message: ", convert_hex_to_text(new_message), "Key:", key, "Ciphertext:", ciphertext_ebc_new)
    # print("AES-128 CBC for the changed message")
    # print("Changed Message: ", convert_hex_to_text(new_message), "Key:", key, "Ciphertext:", ciphertext_cbc_new)

    # Step 7: Calculate the different bits
    count_ebc = count_ebc + count_different_bits(ciphertext_ebc, ciphertext_ebc_new)
    count_cbc = count_cbc + count_different_bits(ciphertext_cbc, ciphertext_cbc_new)

print("Avalanche effect for EBC mode: ", (count_ebc / 50 * 100), "%")
print("Avalanche effect for CBC mode: ", (count_cbc / 50 * 100), "%")
