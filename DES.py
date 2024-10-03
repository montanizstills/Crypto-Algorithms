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


# def stringify_bytes(bytes: bytes) -> str:
#     return ''.join(map(chr, bytes))

def do_IP(binary_pattern):
    ip_txt_str = ""
    IP_Matrix = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    # print(f"Binary Plain Text: {binary_plain_text}")

    for bit_pos in IP_Matrix:
        # print(f"Bit Position: {bit_pos}")
        ip_txt_str += binary_pattern[bit_pos - 1]
        # print(ip_txt_str)

    # return first 32 bits of the IP, then second 32 bits of the IP
    return ip_txt_str[:32], ip_txt_str[32:]


def do_PC_1(key: str):
    # convert key to binary
    binary_key = str_to_binary(key)

    # if key is not 64 bits, pad it with 0s
    if len(binary_key) != 64:
        binary_key += "0" * (64 - len(binary_key))

    PC_1_Matrix = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ]
    binary_key = str_to_binary(key)
    pc_1_key = ""
    for bit_pos in PC_1_Matrix:
        pc_1_key += binary_key[bit_pos - 1]

    # print(f"PC_1 Key length: {len(pc_1_key)}")

    # split the key into two halves, C_0 and D_0
    return pc_1_key[:28], pc_1_key[28:]


def do_Left_Shift(key_subset: str, num_of_bits_to_rotate: int):
    return key_subset[num_of_bits_to_rotate:] + key_subset[:num_of_bits_to_rotate]


def do_Right_Shift(key_subset: str, shift_count: int):
    return key_subset[-shift_count:] + key_subset[:-shift_count]


def do_PC_2(C_i: str, D_i: str):
    PC_2_Matrix = [
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
    for bit_pos in PC_2_Matrix:
        if bit_pos <= 28:
            key_out += C_i[bit_pos - 1]
        else:
            key_out += D_i[bit_pos - 29]

    return key_out


def do_Transform(C_i: str, D_i: str, num_of_bits_to_rotate: int):
    C = do_Left_Shift(C_i, num_of_bits_to_rotate)
    D = do_Left_Shift(D_i, num_of_bits_to_rotate)
    return do_PC_2(C, D)


def do_E_Expansion(binary_block):
    Expansion_Table = [
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
    for bit_pos in Expansion_Table:
        expanded_block += binary_block[bit_pos - 1]
    return expanded_block
    pass


def do_S_Box_Substitution(binary_block: str, key: str):
    # xor the 48 bit block with the key
    binary_block = do_xor(binary_block, key)

    # take the 48 bit block and split it into 8 6-bit blocks
    binary_blocks = [binary_block[i:i + 6] for i in range(0, len(binary_block), 6)]

    # apply the S-boxes to each block
    S_Table_1 = [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ]
    S_Table_2 = [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ]
    S_Table_3 = [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ]
    S_Table_4 = [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ]
    S_Table_5 = [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ]
    S_Table_6 = [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ]
    S_Table_7 = [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ]
    S_Table_8 = [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
    S_Boxes = [S_Table_1, S_Table_2, S_Table_3, S_Table_4, S_Table_5, S_Table_6, S_Table_7, S_Table_8]
    s_box_output = ""
    for i, block in enumerate(binary_blocks):
        row = int(block[0] + block[-1], 2)
        col = int(block[1:-1], 2)
        s_box_output += format(S_Boxes[i][row][col], '08b')

    # return the 32 bit block
    return s_box_output


def do_permutation(binary_string: str):
    P_Table = [
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
    ]
    permuted_block = ""
    for bit_pos in P_Table:
        permuted_block += binary_string[bit_pos - 1]
    return permuted_block


def do_fn(r_i, key_i):
    expanded_block = do_E_Expansion(key_i, r_i)
    xor_result = do_xor(expanded_block, key_i)
    substituted_block_result = do_S_Box_Substitution(xor_result, key_i)
    permutation_result = do_permutation(substituted_block_result)
    return permutation_result


def do_xor(x, y):
    # x and y are binary strings
    return "".join(str(int(a) ^ int(b)) for a, b in zip(x, y))


def do_ip_final(binary_block: str):
    pass


if __name__ == "__main__":
    binary_str = '0'*64
    print(f"Binary String: {binary_str}")
    print(f"IP(x of zeros): {do_IP(binary_str)}")
