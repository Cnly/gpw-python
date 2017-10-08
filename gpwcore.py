import base64
import hashlib

salt_bytes = b'YjBjNWM4YjJkODBlMzJmOWYzOWY4ZDgxY2VkODdiNWI5OTgxMDE4MjFhZjcwMWM2M2Q'
b64_alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' + '0123456789' + '+/'  # 64 chars
# Below are 2 predefined sets of chars that will appear in the final password
chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' + '0123456789' + '~`!@#$%^&*()_-+={[}]|:;<,>.?/'  # 91 chars
chars_weaker = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' + '0123456789' + '~!@#$%&_-+=?'  # 74 chars

def s2b(s: str):
    return bytes(s, 'utf-8')


def preprocess(password: str, key: str, target_len: int=16):
    assert target_len in (16, 24, 32)
    ret = salt_bytes + s2b(password + key)
    ret = hashlib.sha512(ret).digest()
    ret = hashlib.sha512(salt_bytes + ret).digest()
    ret = hashlib.sha512(salt_bytes + ret).digest()
    if target_len == 16:  # 12 bytes required
        ret = hashlib.sha1(salt_bytes + ret).digest()
    elif target_len == 24:  # 18 bytes required
        ret = hashlib.sha256(salt_bytes + ret).digest()
    else:  # target_len == 32; 24 bytes required
        ret = hashlib.sha512(salt_bytes + ret).digest()
    return ret


def generate_alphabet(preprocessed: bytes, chars_avail: str=chars):
    rules = hashlib.sha512(salt_bytes + preprocessed).digest()  # 64 bytes
    alphabet = []
    len_chars = len(chars_avail)
    for i in range(0, 64):  # 64 == len(b64_alphabet)
        f = rules[i] % len_chars
        y = chars_avail[f]
        alphabet.append(y)
    return alphabet


def finalise(preprocessed: bytes, alphabet: list, target_len: int=16):
    assert target_len in (16, 24, 32)
    original = base64.b64encode(preprocessed).decode('utf-8')
    ret = ''
    for i in range(target_len):
        char = original[i]
        index = b64_alphabet.find(char)
        char = alphabet[index]
        ret += char
    return ret


def gpw(password: str, key: str, target_len: int=16, chars_avail: str=chars):
    assert target_len in (16, 24, 32)
    p = preprocess(password, key, target_len=target_len)
    a = generate_alphabet(p, chars_avail=chars_avail)
    return finalise(p, a, target_len)


def gpw_random():
    raise NotImplementedError()
