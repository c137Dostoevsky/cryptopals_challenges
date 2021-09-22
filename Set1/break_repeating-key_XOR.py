# encoding: utf-8
# python 3.9

import string
import re
import base64

def hammingDistance(b1, b2):
    """Compute the edit Hamming distance between two bytes, return int"""
    res = bytes()
    for i in range(len(b1)):
        res += bytes([ord(b1[i:i+1]) ^ ord(b2[i:i+1])])
    count = 0
    for i in range(len(res)):
        ri = res[i]
        while ri:
            count += ri & 1
            ri >>= 1
    return count

def singleXOR(cipher):
    """Decrypt xor'd bytes with brute force, return the first single char key str"""
    for j in string.printable:
        result = bytes()
        for i in range(0, len(cipher), 1):
            result += bytes([ord(cipher[i:i+1]) ^ ord(j)])
        res = re.search(r"((\w+)(\s+)){3,}", str(result))
        if res is None:
            continue
        #print(f"[+] xor key: {j}")
        #print(f"[+] Palin text : {result.decode()}")
        break
    return j

def repeatXOR(ciph, key="ICE"):
    """En-De bytes with repeating-key XOR bytes, return bytes"""
    result = bytes()
    for i in range(0, len(ciph), 1):
        result += bytes([ord(ciph[i:i+1]) ^ ord(key[i % len(key)])])
    return result

if __name__ == '__main__':
    # https://cryptopals.com/sets/1/challenges/6
    # download 6.txt from https://cryptopals.com/static/challenge-data/6.txt
    
    with open("6.txt") as ff:
        ciph = base64.b64decode(ff.read())
    '''
    # find smallest normalized edit distance
    d = dict()
    for size in range(2, 41, 1):
        ciph1 = ciph[0:size]
        ciph2 = ciph[size:size*2]
        ciph3 = ciph[size*2:size*3]
        ciph4 = ciph[size*3:size*4]
        hd = hammingDistance(ciph1, ciph2) + hammingDistance(ciph1, ciph3) + hammingDistance(ciph1, ciph4) + hammingDistance(ciph2, ciph3) + hammingDistance(ciph2, ciph4) + hammingDistance(ciph3, ciph4)
        d[size] = hd/size
    print(d.items())
    print(sorted(d.values()))
    # 2 blocks: {2: 2.5, 3: 2.0, 4: 3.5, 5: 1.2, 6: 4.0, 7: 3.0, 8: 3.0, 9: 3.5555555555555554, 10: 3.3, 11: 2.6363636363636362, 12: 3.25, 13: 2.5384615384615383, 14: 3.2142857142857144, 15: 2.933333333333333, 16: 3.0, 17: 2.9411764705882355, 18: 2.7777777777777777, 19: 3.3157894736842106, 20: 2.7, 21: 3.0476190476190474, 22: 3.727272727272727, 23: 3.1739130434782608, 24: 3.375, 25: 3.24, 26: 3.5, 27: 3.4814814814814814, 28: 3.5357142857142856, 29: 3.206896551724138, 30: 3.433333333333333, 31: 3.096774193548387, 32: 3.4375, 33: 3.272727272727273, 34: 3.323529411764706, 35: 3.257142857142857, 36: 3.4166666666666665, 37: 3.108108108108108, 38: 2.8684210526315788, 39: 3.3076923076923075}
    # 4 blocks: dict_items([(2, 18.0), (3, 18.666666666666664), (4, 20.0), (5, 17.400000000000002), (6, 18.5), (7, 18.428571428571427), (8, 18.75), (9, 19.11111111111111), (10, 19.2), (11, 20.545454545454547), (12, 20.75), (13, 19.923076923076923), (14, 20.071428571428573), (15, 19.666666666666664), (16, 19.25), (17, 19.235294117647058), (18, 19.500000000000004), (19, 18.57894736842105), (20, 18.6), (21, 19.809523809523807), (22, 20.272727272727273), (23, 19.56521739130435), (24, 18.125), (25, 19.880000000000003), (26, 19.5), (27, 20.074074074074076), (28, 18.928571428571427), (29, 16.482758620689655), (30, 19.066666666666666), (31, 19.870967741935484), (32, 19.5625), (33, 19.727272727272727), (34, 19.08823529411765), (35, 19.82857142857143), (36, 20.305555555555557), (37, 19.513513513513512), (38, 19.60526315789474), (39, 19.17948717948718)])
    # sorted: [16.482758620689655, 17.400000000000002, 18.0, 18.125, 18.428571428571427, 18.5, 18.57894736842105, 18.6, 18.666666666666664, 18.75, 18.928571428571427, 19.066666666666666, 19.08823529411765, 19.11111111111111, 19.17948717948718, 19.2, 19.235294117647058, 19.25, 19.5, 19.500000000000004, 19.513513513513512, 19.5625, 19.56521739130435, 19.60526315789474, 19.666666666666664, 19.727272727272727, 19.809523809523807, 19.82857142857143, 19.870967741935484, 19.880000000000003, 19.923076923076923, 20.0, 20.071428571428573, 20.074074074074076, 20.272727272727273, 20.305555555555557, 20.545454545454547, 20.75]
    KEYSIZE may be 29,5,2
    '''
    sizes = [29,5,2]
    for size in sizes:
        keys = ""
        # break the ciphertext into blocks of KEYSIZE length, transpose the blocks
        block = dict()
        for j in range(0, size, 1):
            temp = bytes()
            for i in range(j, len(ciph), size):
                temp += ciph[i:i+1]
            block[j] = temp
        # Solve each block as if it was single-character XOR
        for i in range(size):
            keys += singleXOR(block[i])
        print(f"[+] Key may be : {keys}")
    # key:  Terminator X: Bring the noise

    print(repeatXOR(ciph, key="Terminator X: Bring the noise").decode())
    # "I'm back and I'm ringin' the bell
    # A rockin' on the mike while the fly girls yell......"
