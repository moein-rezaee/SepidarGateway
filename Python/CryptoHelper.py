from base64 import b64encode, b64decode
from xml.etree.ElementTree import fromstring
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad


def aes_encrypt(key: str, plain_text: str):
    key = str.encode(key)
    data = str.encode(plain_text)

    aes_cipher = AES.new(key, AES.MODE_CBC)
    cipher_bytes = aes_cipher.encrypt(pad(data, AES.block_size))

    iv = b64encode(aes_cipher.iv).decode('utf-8')
    cipher = b64encode(cipher_bytes).decode('utf-8')

    return {'iv': iv, 'cipher': cipher}


def aes_decrypt(key: str, cipher: str, iv: str):
    key = str.encode(key)
    data = b64decode(cipher)
    iv = b64decode(iv)

    aes_cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(aes_cipher.decrypt(data), AES.block_size)

    return plain_text


def rsa_encrypt(public_key: str, plain_text: bytes):
    xml = fromstring(public_key)
    modulus = int.from_bytes(b64decode(xml.find('Modulus').text), 'big')
    exponent = int.from_bytes(b64decode(xml.find('Exponent').text), 'little')
    key = RSA.construct((modulus, exponent))
    encryptor = PKCS1_v1_5.new(key)
    encrypted = encryptor.encrypt(plain_text)
    return encrypted


def md5_hash(text: str):
    hasher = MD5.new()
    hasher.update(str.encode(text))
    return hasher.hexdigest()
