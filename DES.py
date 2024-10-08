def str_to_binary(string: str):
    binary_block = "".join(format(ord(char), 'b') for char in string)
    # if binary_block is not a 64 bit block, pad it with 0s
    if len(binary_block) % 64 != 0:
        binary_block += "0" * (64 - len(binary_block))
    return binary_block


def binary_to_decimal(binary_block: str):
    return int(binary_block, 2)


def hex_to_binary(hex_string: str):
    return bin(int(hex_string, 16))[2:].zfill(64)


def stringify_bytes(bytes: bytes) -> str:
    return ''.join(map(chr, bytes))

def binary_to_str(binary_str):
    return ''.join(chr(int(binary_str[i:i + 8], 2)) for i in range(0, len(binary_str), 8))

def do_ip(binary_pattern):
    ip_txt_str = ""
    ip_matrix = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    for bit_pos in ip_matrix:
        ip_txt_str += binary_pattern[bit_pos - 1]

    # return first 32 bits of the IP, then second 32 bits of the IP
    return ip_txt_str[:32], ip_txt_str[32:]


def do_pc_1(binary_key):
    # # if key is not 64 bits, pad it with 0s
    # if len(binary_key) != 64:
    #     binary_key += "0" * (64 - len(binary_key))

    pc_1_matrix = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ]

    pc_1_key = ""
    for bit_pos in pc_1_matrix:
        pc_1_key += binary_key[bit_pos - 1]

    # split the key into two halves, C_0 and D_0
    return pc_1_key[:28], pc_1_key[28:]


def replace_parity_bits(binary_str: str, replacement:str):
    str_op_removal = ""
    for pos, bit in enumerate(binary_str):
        if (pos + 1) % 8 == 0:  # PEMDAS modulus
            str_op_removal += replacement
        else:
            str_op_removal += bit
    return str_op_removal


def do_left_shift(key_subset, num_of_bits_to_rotate: int):
    # print(f"l_half: {key_subset[:num_of_bits_to_rotate]}")
    # print(f"r_half: {key_subset[num_of_bits_to_rotate:]}")
    return key_subset[num_of_bits_to_rotate:] + key_subset[:num_of_bits_to_rotate]


def do_right_shift(key_subset, num_of_bits_to_rotate: int):
    # print(f"l_half: {key_subset[:num_of_bits_to_rotate]}")
    # print(f"r_half: {key_subset[num_of_bits_to_rotate:]}")
    return key_subset[-num_of_bits_to_rotate:] + key_subset[:-num_of_bits_to_rotate]


def do_shift(key_subset, shift_count: int, decryption: bool = False):
    if decryption:
        return do_right_shift(key_subset, 1) if shift_count in [2, 9, 16] else do_right_shift(key_subset, 2)
    return do_left_shift(key_subset, 1) if shift_count in [1, 2, 9, 16] else do_left_shift(key_subset, 2)


def do_rotate(key_subset, shift_count: int):
    key_out = key_subset
    for round in range(1, shift_count + 1):
        key_out = do_shift(key_out, round)
    return key_out


def do_pc_2(c_in, d_in):
    pc_2_matrix = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ]
    key_out = ""
    for bit_pos in pc_2_matrix:
        if bit_pos <= 28:
            key_out += c_in[bit_pos - 1]
        else:
            key_out += d_in[bit_pos - 29]

    return key_out


def do_e_expansion(binary_block):
    expansion_table = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]
    expanded_block = ""
    for bit_pos in expansion_table:
        expanded_block += binary_block[bit_pos - 1]
    return expanded_block


def do_s_box_substitution(binary_block):
    # take the 48 bit block and split it into 8 6-bit blocks
    binary_blocks = [binary_block[i:i + 6] for i in range(0, len(binary_block), 6)]

    # apply the S-boxes to each block
    s_table_1 = [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ]
    s_table_2 = [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ]
    s_table_3 = [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ]
    s_table_4 = [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ]
    s_table_5 = [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ]
    s_table_6 = [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ]
    s_table_7 = [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ]
    s_table_8 = [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
    s_boxes = [s_table_1, s_table_2, s_table_3, s_table_4, s_table_5, s_table_6, s_table_7, s_table_8]
    s_box_output = ""
    # for each 6 bit block, get the row and column values
    for i, block in enumerate(binary_blocks):
        # get the row and column values
        row = int(block[0] + block[-1], 2)
        col = int(block[1:-1], 2)
        # get the value from the S-box
        s_box_output += format(s_boxes[i][row][col], '08b')

    # return the 32 bit block
    return s_box_output


def do_permutation(binary_block):
    p_table = [
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
    ]
    permuted_block = ""
    for bit_pos in p_table:
        permuted_block += binary_block[bit_pos - 1]
    return permuted_block


def do_fn(r_i, key_i):
    expansion_block_result = do_e_expansion(r_i)
    xor_result = do_xor(expansion_block_result, key_i)
    substituted_block_result = do_s_box_substitution(xor_result)
    permutation_block_result = do_permutation(substituted_block_result)
    return permutation_block_result


def do_xor(x, y):
    # x and y are binary strings
    return "".join(str(int(a) ^ int(b)) for a, b in zip(x, y))


def do_ip_final(binary_block):
    ip_matrix = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ]
    ip_txt_str = ""
    for bit_pos in ip_matrix:
        ip_txt_str += binary_block[bit_pos - 1]
    return ip_txt_str


def run(binary_str, binary_key, decryption: bool = False):
    # convert from hex to binary
    # binary_str = hex_to_binary(binary_str)

    # Initial Permutation
    l, r = do_ip(binary_str)
    # Permuted Choice 1
    c, d = do_pc_1(binary_key)

    # Transform the key
    c_out, d_out = do_shift(c, 1), do_shift(d, 1, decryption)
    key_out = do_pc_2(c_out, d_out)

    # F-Function
    expanded_block = do_e_expansion(r)
    e_xor_k = do_xor(expanded_block, key_out)
    s_box_substitution = do_s_box_substitution(e_xor_k)
    permuted_block = do_permutation(s_box_substitution)
    fn_output = do_fn(r, key_out)

    # L0 XOR F(R0, K1)
    l_xor_fn = do_xor(l, fn_output)
    round_1 = r + l_xor_fn

    print(f"Binary String: {binary_str}")
    print(f"Binary Key: {binary_key}")
    print(f"IP: {do_ip(binary_str)}")

    print(f"PC_1: {do_pc_1(binary_key)}")
    print(f"Transformed Key: {key_out}")

    print(f"Expansion: {expanded_block}")
    print(f"Expanded XOR Key: {e_xor_k}")
    print(f"S-Box Substitution: {s_box_substitution}")
    print(f"Permutation: {permuted_block}")

    print(f"Left XOR Function: {l_xor_fn}")
    print(f"Round 1: {round_1}")


def run_decryption(binary_str, binary_key):
    l, r = do_ip(binary_str)
    c, d = do_pc_1(binary_key)

    # Transform the key


if __name__ == "__main__":
    print(f"Question 2:")
    binary_str = '0' * 64
    binary_key = '0' * 64
    run(binary_str, binary_key)
    print("\n")

    print(f"Question 3:")
    binary_str = '1' * 64
    binary_key = '1' * 64
    run(binary_str, binary_key)
    print("\n")

    print(f"Question 4:")
    binary_str = '1' * 64
    binary_key = '1' * 64
    run(binary_str, binary_key, True)
    print("\n")

    print(f"Question 5:")
    hex_key = "0123456789ABCDEF"
    print(f"Hex Key: {hex_key}")
    binary_key = hex_to_binary(hex_key)
    print(f"Binary Key: {binary_key}")

    c, d = do_pc_1(binary_key)
    custom_key = replace_parity_bits(binary_key)
    print(f"Custom Key: {custom_key}")
    print(f"PC-1: {c + d}")

    c9 = do_rotate(c, 9)
    d9 = do_rotate(d, 9)
    print(f"key9: {c9 + d9}")


    c16 = do_rotate(c, 16)
    d16 = do_rotate(d, 16)
    print(f"key16: {c16 + d16}")
    print(f"key0 ?== key16: {c + d == c16 + d16}")
