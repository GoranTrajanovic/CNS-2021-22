from turtle import circle
import requests
import sys

from base64 import b64decode
from http import HTTPStatus
from pydantic import BaseModel

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class Ciphertext(BaseModel):
    ciphertext: str


class Challenge(BaseModel):
    iv: str
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


def decrypt_challenge(key: bytes, challenge: Challenge) -> str:
    """Decrypts encrypted challenge; reveals a password that can be
    used to unlock the next task/challenge.
    """
    iv = b64decode(challenge.iv)
    ciphertext = b64decode(challenge.ciphertext)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext)
    plaintext += decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(plaintext)
    plaintext += unpadder.finalize()
    return plaintext.decode()


def get_token(url, username, password):
    response = requests.post(
        url=url,
        headers={
            "accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        },
        data = {
            "username": username,
            "password": password
        }        
    )    
    http_status_code = response.status_code
    token = response.json().get("access_token")
    return http_status_code, token


#def encrypt_chosen_plaintext(url, token, plaintext):
    response = requests.post(
        url=url,
        headers={
            "accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },    
        json = {"plaintext": plaintext}
    )    
    http_status_code = response.status_code
    ciphertext = response.json().get("ciphertext")
    return http_status_code, ciphertext    


#def get_challenge(url):
    response = requests.get(url)
    http_status_code = response.status_code
    challenge = response.json()
    return http_status_code, challenge    


def get_encrypt_cookie(host):
    response = requests.get(
        url=f"http://{host}/cbc/iv/encrypted_cookie"
    )
    assert response.status_code == 200
    iv = response.json().get("iv")
    ciphertext = response.json().get("ciphertext")
    return iv, ciphertext

def get_current_iv(host, token):
    response = requests.post(
        url=f"http://{host}/cbc/iv",
        headers={
            "accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        json={
            "plaintext": b"dummy".hex()
        }   
    )
    assert response.status_code == 200
    iv = response.json().get("iv")
    return iv


def get_wordlist(host):
    response = requests.get(
        url=f"http://{host}/static/wordlist.txt"
    )
    assert response.status_code == 200
    return response.content

def add_padding(word: bytes):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(word)
    padded_data += padder.finalize()
    return padded_data


def encrypt_chosen_plaintext(host, token, plaintext):
    response = requests.post(
        url=f"http://{host}/cbc/iv",
        headers={
            "accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        json={
            "plaintext": plaintext
        }   
    )
    assert response.status_code == 200
    iv = response.json().get("iv")
    ciphertext = response.json().get("ciphertext")
    return iv, ciphertext

def print_table(table):
    for key, value in table.items():
        print(f"\t{key:_<25}{value:>5}")
    print("\n")

if __name__ == '__main__':
    # 1. GET the authorization token
    host = "10.0.15.8"
    path = "cbc/token"
    url = f"http://{host}/{path}"
    username = "trajanovic_goran",
    password = "ailsiakind"

    http_status_code, token = get_token(
        url=url, 
        username=username, 
        password=password
    )
    if http_status_code != HTTPStatus.OK:
        sys.exit(f"HTTP Error {http_status_code} {HTTPStatus(http_status_code).phrase} :-(")
    # print(f"Authorization token: {token}")

    # plan:
    # 1. Get cookie IV and ciphertext
    cookie_iv, cookie_ciphertext = get_encrypt_cookie(host)
    cookie_iv = b64decode(cookie_iv)
    cookie_iv = int.from_bytes(cookie_iv, byteorder="big")
    print(f"\tCookie iv: {cookie_iv}")
    print(f"\tCookie ciphertext: {cookie_ciphertext}")

    # 2. Get current IV (next will be current + const), where const is 4
    current_iv = get_current_iv(host, token)
    current_iv = b64decode(current_iv)
    current_iv = int.from_bytes(current_iv, byteorder="big")
    print(f"\tCurrent IV: {current_iv}")
    # 3. Get the wordlist
    print("\nGet the worddlist and interate over it")
    wordlist = get_wordlist(host)

    # 4. Iterate over the list and prepare plaintext
    # for word in wordlist.split():
    #     table_to_print = {}

    #     print(f"\t[*] Testing word: {word}")
    #     next_iv = current_iv + 4

    #     table_to_print['Cookie IV'] = cookie_iv
    #     table_to_print['Next IV'] = next_iv

    #     # 4.1 Pad the word
    #     padded_word = add_padding(word)
    #     table_to_print['Padded word'] = padded_word.hex()
    #     padded_word = int.from_bytes(padded_word, byteorder="big")


    #     # Prepare plaintext
    #     plaintext = padded_word ^ cookie_iv ^ next_iv
    #     plaintext = plaintext.to_bytes(16, "big").hex()
    #     table_to_print['Current plaintext'] = plaintext

    #     # Send chosen plaintext to the oracle
    #     iv, ciphertext = encrypt_chosen_plaintext(host, token, plaintext)
    #     iv = b64decode(iv)
    #     current_iv = int.from_bytes(iv, "big")

    #     table_to_print['Cookie ciphertext'] = b64decode(cookie_ciphertext).hex()
    #     table_to_print['Current ciphertext'] = b64decode(ciphertext).hex()

    #     print_table(table_to_print)

    #     # Check if collision on 1st block
    #     if ciphertext[:16] == cookie_ciphertext[:16]:
    #         print(f"\t========= \tThe sought cookie is: {word} \t=========")
    #         break

    #     # the cookie is: exerciser



# Decryption

# {
#   "iv": "/Phu/83vsyCfpcTjBqchyQ==",
#   "ciphertext": "JiJ6qmuqlva8v6KZDpGVu2vtS+W30MkATJ+SpSPPfGZaXGlGMhXyq8wixD3XEI+gHILoM9+d6v/prSIWBNwC1w=="
# }

challenge = Challenge(
    iv="/Phu/83vsyCfpcTjBqchyQ==",
    ciphertext="JiJ6qmuqlva8v6KZDpGVu2vtS+W30MkATJ+SpSPPfGZaXGlGMhXyq8wixD3XEI+gHILoM9+d6v/prSIWBNwC1w=="
)

cookie="exerciser"

# 4. Derive the key and decrypt the challenge
print(f"\nDerive a decryption key from the cookie")
key = derive_key(cookie)

print(f"\nDecrypt the challenge")
decrypted_challenge = decrypt_challenge(key, challenge)
print(f"\tDecrypted challenge: {decrypted_challenge}")


# {
#   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0cmFqYW5vdmljX2dvcmFuIiwic2NvcGUiOiJjYmMiLCJleHAiOjE2NDkxNDQ1ODN9.LIWDCugXey__qFXYqIX9mtKsYtMcQB-eVhcvP8EvPfc",
#   "token_type": "bearer"
# }

# {
#   "iv": "OzSm+ogAPeZSWFVg/2yPBg==",
#   "ciphertext": "+mTV0e1rkpCl5yLCjt2bqSkFwoTIRcR8cpUXmWi1XIZSmGJ1a+6zsHnMKJBfRri9jxAlNlAOxsd+PUnlZgF1zQ=="
# }