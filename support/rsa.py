import random
from math import gcd

# Check if a number is prime


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

# Generate a random prime number


def generate_prime_number() -> int:
    while True:
        p = random.randint(2, 10**5)
        if is_prime(p):
            return p

# Compute the modular inverse using the extended Euclidean algorithm


def mod_inverse(a: int, m: int) -> int:
    if gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (
            u1 - q * v1,
            u2 - q * v2,
            u3 - q * v3,
            v1,
            v2,
            v3,
        )
    return u1 % m

# Generate public key and private key


def generate_keys(p: int, q: int) -> tuple:
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(1, phi)
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)
    d = mod_inverse(e, phi)
    return e, d, n, phi


def encrypted(plaintext: str, n: int, public_key: int):
    ciphertext = ""
    for c in plaintext:
        m = ord(c)
        ciphertext += str(pow(m, public_key, n)) + " "
    return ciphertext


def decrypted(ciphertext: str, n: int, private_key: int):
    plaintext = ""
    parts = ciphertext.split()
    for part in parts:
        if part:
            c = int(part)
            try:
                plaintext += chr(pow(c, private_key, n))
            except ValueError:
                return False
            except OverflowError:
                return False
    return plaintext


class RSA(object):
    def __init__(self, p=0, q=0) -> None:
        if p != 0 and q != 0:
            self.p = p
            self.q = q
            self.e, self.d, self.N, self.phi = generate_keys(p, q)
        else:
            self.p = generate_prime_number()
            self.q = generate_prime_number()
            self.e, self.d, self.N, self.phi = generate_keys(self.p, self.q)

    # Encrypt the plaintext message using the public key
    def encrypt(self, plaintext: str) -> str:
        ciphertext = ""
        for c in plaintext:
            m = ord(c)
            ciphertext += str(pow(m, self.e, self.N)) + " "
        return ciphertext

    # Decrypt the ciphertext message using the private key
    def decrypt(self, ciphertext: str) -> str:
        plaintext = ""
        parts = ciphertext.split()
        for part in parts:
            if part:
                c = int(part)
                plaintext += chr(pow(c, self.d, self.N))
        return plaintext
