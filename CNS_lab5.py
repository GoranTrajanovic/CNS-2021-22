# In Lab - username: trajanovic_goran pass: lesfuthane


from turtle import circle
from numpy import byte
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
        data={
            "username": username,
            "password": password
        }
    )
    http_status_code = response.status_code
    token = response.json().get("access_token")
    return http_status_code, token


def encrypt_chosen_plaintext(host, token, plaintext):
    response = requests.post(
        url=f"http://{host}/ctr",
        headers={
            "accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        json={"plaintext": plaintext}
    )
    assert response.status_code == 200
    ciphertext = response.json().get("ciphertext")
    nonce = response.json().get("nonce")
    return ciphertext, nonce


def get_challenge(host):
    response = requests.get(
        url=f"http://{host}/ctr/challenge"
    )
    response.raise_for_status()
    ciphertext = response.json().get("ciphertext")
    nonce = response.json().get("nonce")
    return ciphertext, nonce


if __name__ == '__main__':
    # 1. GET the authorization token
    host = "10.0.15.8"
    path = "ctr/token"
    url = f"http://{host}/{path}"
    username = "trajanovic_goran",
    password = "lesfuthane"

    http_status_code, token = get_token(
        url=url,
        username=username,
        password=password
    )
    if http_status_code != HTTPStatus.OK:
        sys.exit(
            f"HTTP Error {http_status_code} {HTTPStatus(http_status_code).phrase} :-(")
    print(f"Authorization token: {token}")

    # 2. GET Challenge
    challenge_ciphertext, challenge_nonce = get_challenge(host)
    # print(f"\nCiphertext: {challenge_ciphertext}")
    # print(f"\nNonce: {challenge_nonce}")
    challenge_ciphertext = b64decode(challenge_ciphertext)
    # because CTR mode - no padding
    plaintext_length = len(challenge_ciphertext)
    plaintext = "x"*plaintext_length

    # 3. Iterate until nonce repeats
    nonce = None 
    ciphertext = None
    counter = 0

    while challenge_nonce != nonce:
        if not (counter + 1) % 50:
            print(f"[*] Request count: {counter + 1:,}", end="\r")

        ciphertext, nonce = encrypt_chosen_plaintext(host, token, plaintext)
        counter += 1

    # 4. Vrtimo: Decrypted_challenge = ciphertext ^ challenge_ciphertext ^ plaintext
    ciphertext = b64decode(ciphertext)
    ciphertext = int.from_bytes(ciphertext, byteorder="big")
    challenge_ciphertext = int.from_bytes(challenge_ciphertext, byteorder="big")
    plaintext = int.from_bytes(plaintext.encode(), byteorder="big")

    decrypted_challenge = ciphertext ^ challenge_ciphertext ^ plaintext

    decrypted_challenge = decrypted_challenge.to_bytes(plaintext_length, byteorder="big")
    decrypted_challenge = decrypted_challenge.decode()

    print(f"Decrypted challenge: {decrypted_challenge}")
    # print(f"\nCiphertext: {challenge_ciphertext}")
    # print(f"\nNonce: {challenge_nonce}")

    # (old) plan:
    # 1. Get cookie IV and ciphertext
    # cookie_iv, cookie_ciphertext = get_encrypt_cookie(host)
    # cookie_iv = b64decode(cookie_iv)
    # cookie_iv = int.from_bytes(cookie_iv, byteorder="big")
    # print(f"\tCookie iv: {cookie_iv}")
    # print(f"\tCookie ciphertext: {cookie_ciphertext}")


#result: Chuck Norris plays racquetball with a waffle iron and a bowling ball. (ASYMMETRIC: franstshen)