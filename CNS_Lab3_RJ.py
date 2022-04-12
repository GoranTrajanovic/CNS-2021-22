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


def encrypt_chosen_plaintext(url, token, plaintext):
    response = requests.post(
        url=url,
        headers={
            "accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        json={"plaintext": plaintext}
    )
    http_status_code = response.status_code
    ciphertext = response.json().get("ciphertext")
    return http_status_code, ciphertext


def get_challenge(url):
    response = requests.get(url)
    http_status_code = response.status_code
    challenge = response.json()
    return http_status_code, challenge


USERNAME = "trajanovic_goran"
PASSWORD = "iberathedf"

if __name__ == '__main__':
    # 1. GET the authorization token
    host = "localhost"
    path = "ecb/token"
    url = f"http://{host}/{path}"
    username = USERNAME,
    password = PASSWORD

    http_status_code, token = get_token(
        url=url,
        username=username,
        password=password
    )
    if http_status_code != HTTPStatus.OK:
        sys.exit(
            f"HTTP Error {http_status_code} {HTTPStatus(http_status_code).phrase} :-(")
    print(f"Authorization token: {token}")

    # 2. Start chosen-plaintext attack (POST plaintext /ecb)
    COOKIE_SIZE = 16
    BLOCK_SIZE = 16
    ALPHABET = "abcdefghijklmnopqrstuvwxyz"
    cookie = ""

    path = "ecb/"
    url = f"http://{host}/{path}"
    for i in range(1, COOKIE_SIZE + 1):
        prefix = "x"*(BLOCK_SIZE - i)
        url = url
        http_status_code, ciphertext = encrypt_chosen_plaintext(
            url=url,
            token=token,
            plaintext=prefix
        )
        if http_status_code != HTTPStatus.OK:
            sys.exit(
                f"HTTP Error {http_status_code} {HTTPStatus(http_status_code).phrase} :-(")
        print(f"\nTesting block: {ciphertext}")
        # IMPORTANT: mind that ciphertext is b64encoded
        test_block = ciphertext[:BLOCK_SIZE]

        for letter in ALPHABET:
            print(f"\t[*] Testing letter: {letter}", end="\r")
            http_status_code, ciphertext = encrypt_chosen_plaintext(
                url=url,
                token=token,
                plaintext=prefix + cookie + letter
            )
            if http_status_code != HTTPStatus.OK:
                sys.exit(
                    f"HTTP Error {http_status_code} {HTTPStatus(http_status_code).phrase} :-(")
            if ciphertext[:BLOCK_SIZE] == test_block:
                cookie += letter
                print(f"\tCollision detected with block: {ciphertext}")
                print(
                    f"\tGuessed letter {i}/{COOKIE_SIZE}: {letter} (cookie: {cookie})")
                break

    print(f"\n======== The sought cookie is: '{cookie}' ========")

    # 3. Get the challenge
    path = "ecb/challenge"
    url = f"http://{host}/{path}"

    print(f"\nGet the challenge to decrypt")
    http_status_code, challenge = get_challenge(url)
    if http_status_code != HTTPStatus.OK:
        sys.exit(
            f"HTTP Error {http_status_code} {HTTPStatus(http_status_code).phrase} :-(")

    challenge = Challenge(
        iv=challenge.get("iv"),
        ciphertext=challenge.get("ciphertext")
    )
    print(f"\tChallenge: {challenge}")

    # 4. Derive the key and decrypt the challenge
    print(f"\nDerive a decryption key from the cookie")
    key = derive_key(cookie)
    print(f"\tDecryption key: {key}")

    print(f"\nDecrypt the challenge")
    decrypted_challenge = decrypt_challenge(key, challenge)
    print(f"\tDecrypted challenge: {decrypted_challenge}")
