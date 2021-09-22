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
    """Encode hex encoded bytes, return base64 bytes"""

    hexbytes = codecs.decode(hexstr, encoding='hex')
    return base64.b64encode(hexbytes)

def fixedXOR(hexstr1, hexstr2):
    """Encode two equal-length hex encoded bytes, return their XOR combination bytes"""

    b1 = codecs.decode(hexstr1, encoding='hex')
    b2 = codecs.decode(hexstr2, encoding='hex')
    res = bytes()
    for i in range(len(b1)):
        res += bytes([ord(b1[i:i + 1]) ^ ord(b2[i:i + 1])])
    return res


def singleXOR(cipher):
    """Decrypt xor'd hex encoded bytes with brute-force, return list of single char key,plain text,cipher text"""
    list = []
    ciph = codecs.decode(cipher, encoding='hex')
    for j in string.printable:
        result = bytes()
        for i in range(len(ciph)):
            result += bytes([ord(ciph[i:i + 1]) ^ ord(j)])
        res = re.search(r"((\w+)( +)){4,}", str(result))
        if res is None:
            continue
        # print(f"[+] The xor key is {j}, ord is {ord(j)} ")
        # print(f"[+] Palin text : {result.decode()}")
        keyinfo = {"xorKey": j, "plainText": result, "cipherText": cipher}
        list.append(keyinfo)
    return list


def En_repeatXOR(text, key="ICE"):
    """Encrypt bytes with repeating-key XOR, return hex encoded bytes"""
    result = bytes()
    for i in range(len(text)):
        result += bytes([ord(text[i:i+1]) ^ ord(key[i % len(key)])])
    return result


if __name__ == '__main__':

    # str -> bytes
    #str2bytes = "123"
    #print(bytes(str2bytes.encode()))

    # bytes -> str
    # bytes2str = b"123"
    # print(str(bytes2str))

    # https://cryptopals.com/sets/1/challenges/1
    # hexSS = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    # print(hex2b64(hexSS).decode())
    # res: b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

    # https://cryptopals.com/sets/1/challenges/2
    # print(fixedXOR(b"1c0111001f010100061a024b53535009181c", b"686974207468652062756c6c277320657965").hex())
    # res: '746865206b696420646f6e277420706c6179'

    # https://cryptopals.com/sets/1/challenges/3
    # ss = b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    # print(singleXOR(ss))
    # res: [{'xorKey': 'X', 'plainText': b"Cooking MC's like a pound of bacon", 'cipherText': b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'}]

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
    #res: [{'xorKey': '5', 'plainText': b'Now that the party is jumping\n', 'cipherText': '7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f'}]

    # https://cryptopals.com/sets/1/challenges/5
    # ss = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    # print(En_repeatXOR(ss).hex())
    # res:  0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

    # https://cryptopals.com/sets/1/challenges/7
    # download 7.txt from https://cryptopals.com/static/challenge-data/7.txt
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
    '''
    # res: b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls......

    # https://cryptopals.com/sets/1/challenges/8
    # download 8.txt from https://cryptopals.com/static/challenge-data/8.txt
    '''
    # detect ECB mode
    size = 32  # 16 bytes
    with open('8.txt', 'rb') as ff:
        lines = ff.readlines()
    for line in lines:
        for i in range(0, len(line), size):
            count = line.count(line[i:i + size])
            if count >= 2:
                print(f"[+] The same 16 byte block: {line[i:i + size]}")
                print(f"[+] cipher line: {line}")
                break
    '''
    # res:
    # [+] The same 16 byte block: b'08649af70dc06f4fd5d2d69c744cd283'
    # [+] cipher line: b'd880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a\r\n'

