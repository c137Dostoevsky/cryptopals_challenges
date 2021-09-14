# encoding: utf-8
# Python 3.9
"""
Cryptopals Rule:
Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.
"""

import base64
import string
import codecs
import re


def hex2b64(hexstr):
    """Encode hex encoded str, return base64 str"""

    hexbytes = codecs.decode(hexstr, encoding='hex')
    hexbytes = base64.b64encode(hexbytes)
    return hexbytes.decode()

def fixedXOR(hexstr1, hexstr2):
    """Encode two equal-length hex encoded str, return their XOR combination str"""

    b1 = codecs.decode(hexstr1, encoding='hex')
    b2 = codecs.decode(hexstr2, encoding='hex')
    res = bytes()
    for i in range(len(b1)):
        res += bytes([ord(b1[i:i+1]) ^ ord(b2[i:i+1])])
    return res.hex()


def singleXOR(cipher):
    """Decrypt xor'd hex encoded str with brute-force, return list of single char key,plain text,cipher text"""
    list = []
    ciph = codecs.decode(cipher, encoding='hex')
    for j in string.printable:
        result = bytes()
        for i in range(len(ciph)):
            result += bytes([ord(ciph[i:i+1]) ^ ord(j)])
        res = re.search(r"((\w+)( +)){4,}", str(result))
        if res is None:
            continue
        # print(f"[+] The xor key is {j}, ord is {ord(j)} ")
        # print(f"[+] Palin text : {result.decode()}")
        keyinfo = {"xorKey":j, "plainText":result, "cipherText":cipher}
        list.append(keyinfo)
    return list

def En_repeatXOR(text, key="ICE"):
    """Encrypt str with repeating-key XOR, return hex encoded str"""
    result = bytes()
    for i in range(len(text)):
        result += bytes([ord(text[i]) ^ ord(key[i % len(key)])])
    return result.hex()


if __name__ == '__main__':

    # https://cryptopals.com/sets/1/challenges/1
    #hexSS = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    #print(hex2b64(hexSS))
    #res: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

    # https://cryptopals.com/sets/1/challenges/2
    #print(fixedXOR("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"))
    #res: '746865206b696420646f6e277420706c6179'

    # https://cryptopals.com/sets/1/challenges/3
    #ss = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    #print(singleXOR(ss))

    # https://cryptopals.com/sets/1/challenges/4
    # download 4.txt from https://cryptopals.com/static/challenge-data/4.txt
    '''
    with open("4.txt") as ff:
        lines = ff.readlines()
        for line in lines:
            ll = singleXOR(line.strip())
            if ll:
                print(ll)
    '''

    # https://cryptopals.com/sets/1/challenges/5
    #ss = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    #print(En_repeatXOR(ss))
    #res:  0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

    # https://cryptopals.com/sets/1/challenges/7
    '''
    import base64
    import codecs
    from Crypto.Cipher import AES

    with open('7.txt', 'rb') as ff:
        ciph = ff.read()
    ciph = base64.b64decode(ciph)

    aes = AES.new(b'YELLOW SUBMARINE', AES.MODE_ECB)
    plain = aes.decrypt(ciph)
    print(plain.decode())
    # res: I'm back and I'm ringin' the bell......
    '''
