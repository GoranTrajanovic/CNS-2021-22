from http.cookies import CookieError
import os
import requests
from base64 import b64decode, b64encode
from pydantic import BaseModel, constr
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Ciphertext(BaseModel):
    ciphertext: str

def derive_key(key_seed: str) -> bytes:
    """Derives encryption/decryption key from the given key_seed.
    Uses modern key derivation function (KDF) scrypt.
    """
    kdf = Scrypt(
        salt=b'',
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    key = kdf.derive(key_seed.encode())
    return key


def ecb_encrypt(key: bytes, plaintext: str) -> str:
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode())
    padded_data += padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data)
    # ciphertext = encryptor.update(plaintext.encode())
    ciphertext += encryptor.finalize()

    encoded_ciphertext = b64encode(ciphertext)
    return Ciphertext(ciphertext=encoded_ciphertext)


def ecb_decrypt(key: bytes, ciphertext: str) -> str:
    ciphertext = b64decode(ciphertext)

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext)
    plaintext += decryptor.finalize()

    # unpadder = padding.PKCS7(128).unpadder()
    # plaintext = unpadder.update(plaintext)
    # plaintext += unpadder.finalize()
    # return plaintext.decode()
    return plaintext.hex()




##### ECB mode, block ciphers, HTTP requests


key = derive_key("cookie")

# 1. Block length

result = ecb_encrypt(key, "test"*4*2)
# print(result)

# 2. On padding

# for i in range(1,17):
#     plaintext = "a"*i
#     plaintext_size = len(plaintext)
#     print(f"\nPlain text: {plaintext} ({plaintext_size})")
#     ciphertext = ecb_encrypt(key, plaintext)
#     print(ciphertext)

#     decrypted_result = ecb_decrypt(key, ciphertext.ciphertext)
#     decrypted_result_size = len(decrypted_result)
#     print(f"Decrypted ciphertext: {decrypted_result} ({decrypted_result_size}) ")


# 3. ECB is deterministic

# temp_str = ("x"*16)
# result = ecb_encrypt(key, temp_str)
# print(b64decode(result.ciphertext).hex())
# result = ecb_encrypt(key, temp_str*2+"y")
# print(b64decode(result.ciphertext).hex())


# HTTP GET and POST requests
URL = "http://10.0.15.7/ecb/challenge"
response = requests.get(URL)
iv = response.json().get("iv")
ciphertext = response.json().get("ciphertext")
# print(iv)
# print(ciphertext)


URL = "http://10.0.15.7/ecb/token"
USERNAME = "trajanovic_goran"
PASSWORD = "iberathedf"
DATA = f"grant_type=&username={USERNAME}&password={PASSWORD}&scope=&client_id=&client_secret="

response = requests.post(
    url=URL,
    headers={
        "accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded"
    },
    data = DATA 
    # data = {
    #     "username" : USERNAME,
    #     "password": PASSWORD
    # }    
)

token = response.json().get("access_token")

# print(f"Token:  {token}")


# Koristenje tokena za autentikaciju

# First get the token as shown above
URL = "http://10.0.15.7/ecb"

PLAINTEXT = "0"*15
j = 1
# PLAINTEXT = PLAINTEXT[:15]
# PLAINTEXT = list(PLAINTEXT)
# PLAINTEXT[15] = 'p'
# PLAINTEXT = "".join(PLAINTEXT)


ALPHABET = "A B C D E F G H I K L M N O P Q R S T V X Y Z J U W"
ALPHABET = ALPHABET.split()
ALPHABET_LOWER = []
for letter in ALPHABET:
    ALPHABET_LOWER.append(letter.lower())


for i in "".join((PLAINTEXT, "0")):

    response = requests.post(
        url=URL,
        headers={
            "accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },    
        json = {"plaintext": PLAINTEXT}
    )

    ciphertext = response.json().get("ciphertext")
    ciphertext = b64decode(ciphertext)
    ciphertext = ciphertext.hex()
    cookie_overflow = ciphertext[30:32]
    print(f"Ciphertext: {ciphertext}")
    print(f"Ciphertext: {len(ciphertext)}")


    for letter in ALPHABET_LOWER:

        # PLAINTEXT = "".join((PLAINTEXT,letter))

        response = requests.post(
            url=URL,
            headers={
                "accept": "application/json",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            },    
            json = {"plaintext": PLAINTEXT}
            # json = {"plaintext": "xyzz"}
        )

        ciphertext = response.json().get("ciphertext")
        ciphertext = b64decode(ciphertext)
        ciphertext = ciphertext.hex()
        if (ciphertext[30:32] == cookie_overflow):
            # found = ciphertext[30:32]
            print(f"First letter is: {letter}")
            PLAINTEXT = PLAINTEXT[1:]
            PLAINTEXT = "".join((PLAINTEXT, letter))
            break






