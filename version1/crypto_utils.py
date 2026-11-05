"""Shared number theory, AES, and JSON networking for EL2001 Project 1.

IMPORTANT: Parameters RSA p,q and DH p are deliberately tiny for the
classroom exercise; AES-ECB and repeated DH secrets are NOT production-safe.
"""
import base64
import json
import secrets
import socket

# The provided examples use Crypto.Cipher.AES (pycryptodome).  cryptography
# is supported as a fallback to make the exercise easier to run.
try:
    from Crypto.Cipher import AES
    def _encrypt_block(key, data):
        return AES.new(key, AES.MODE_ECB).encrypt(data)
    def _decrypt_block(key, data):
        return AES.new(key, AES.MODE_ECB).decrypt(data)
except ImportError:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    def _encrypt_block(key, data):
        encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        return encryptor.update(data) + encryptor.finalize()
    def _decrypt_block(key, data):
        decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        return decryptor.update(data) + decryptor.finalize()


class ProtocolError(Exception):
    """Raised for invalid or unexpected messages."""


def is_prime(n):
    """Trial division; sufficient for the required 400..500 interval."""
    if not isinstance(n, int) or isinstance(n, bool) or n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def prime_factors(n):
    """Distinct prime factors."""
    factors = set()
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.add(d)
            n //= d
        d += 1
    if n > 1:
        factors.add(n)
    return factors


def is_generator(g, p):
    """Check if g is a primitive root modulo prime p."""
    if not is_prime(p) or not isinstance(g, int) or isinstance(g, bool):
        return False
    if not 1 < g < p:
        return False
    return all(pow(g, (p - 1) // factor, p) != 1 for factor in prime_factors(p - 1))


def random_prime():
    candidates = [i for i in range(401, 500) if is_prime(i)]
    return secrets.choice(candidates)


def generate_rsa_keypair():
    p = random_prime()
    q = random_prime()
    while q == p:
        q = random_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    # e must be coprime to phi.  Standard e=65537 is valid if possible.
    e = 65537
    import math
    if math.gcd(e, phi) != 1:
        choices = [v for v in range(3, phi, 2) if math.gcd(v, phi) == 1]
        e = secrets.choice(choices)
    d = pow(e, -1, phi)
    return {'p': p, 'q': q, 'n': n, 'e': e, 'd': d}


def verify_rsa_keypair(p, q, e, d):
    import math
    if any(not isinstance(x, int) or isinstance(x, bool) for x in (p, q, e, d)):
        return False
    if not (400 < p < 500 and 400 < q < 500):
        return False
    if p == q or not is_prime(p) or not is_prime(q):
        return False
    phi = (p - 1) * (q - 1)
    if not (1 < e < phi and 1 < d < phi and math.gcd(e, phi) == 1):
        return False
    return (e * d) % phi == 1


def rsa_encrypt_key(key, e, n):
    if len(key) != 32 or n <= 255:
        raise ProtocolError('invalid RSA parameters or AES key length')
    return [pow(byte, e, n) for byte in key]


def rsa_decrypt_key(encrypted_key, d, n):
    if not isinstance(encrypted_key, list) or len(encrypted_key) != 32:
        raise ProtocolError('RSA encrypted_key must contain exactly 32 integers')
    if any(not isinstance(c, int) or isinstance(c, bool) or not 0 <= c < n for c in encrypted_key):
        raise ProtocolError('invalid RSA encrypted_key element')
    values = [pow(c, d, n) for c in encrypted_key]
    if any(v > 255 for v in values):
        raise ProtocolError('decrypted RSA byte out of range')
    return bytes(values)


def dh_keypair(p, g):
    private = secrets.randbelow(p - 3) + 2
    return private, pow(g, private, p)


def dh_aes_key(shared_secret):
    return shared_secret.to_bytes(2, byteorder='big') * 16


def aes_encrypt(key, plaintext):
    """AES-ECB 256-bit, PKCS#7 padding, Base64 text (as in examples)."""
    if len(key) != 32:
        raise ProtocolError('AES-256 needs a 32-byte key')
    data = plaintext.encode('utf-8')
    pad = 16 - len(data) % 16
    padded = data + bytes([pad]) * pad
    return base64.b64encode(_encrypt_block(key, padded)).decode('ascii')


def aes_decrypt(key, encoded):
    if len(key) != 32:
        raise ProtocolError('AES-256 needs a 32-byte key')
    try:
        data = base64.b64decode(encoded, validate=True)
        if not data or len(data) % 16:
            raise ValueError('invalid ciphertext size')
        decrypted = _decrypt_block(key, data)
        pad = decrypted[-1]
        if not (1 <= pad <= 16) or decrypted[-pad:] != bytes([pad]) * pad:
            raise ValueError('invalid PKCS#7 padding')
        return decrypted[:-pad].decode('utf-8')
    except (ValueError, UnicodeDecodeError, TypeError) as err:
        raise ProtocolError(f'could not decrypt AES message: {err}') from err


class JSONConnection:
    """Read one JSON object even if TCP splits/joins packets.

    Uses newline as a send separator, but accepts messages without a newline
    so the included professor examples and their JSON wire format still work.
    """
    def __init__(self, sock, observer=None):
        self.sock = sock
        self.observer = observer
        self.buffer = ''
        self.decoder = json.JSONDecoder()

    def send(self, msg):
        payload = json.dumps(msg, separators=(',', ':'), ensure_ascii=True)
        self.sock.sendall((payload + '\n').encode('ascii'))
        print('Sent:', payload, flush=True)
        if self.observer is not None:
            self.observer('sent', msg)

    def recv(self):
        while True:
            self.buffer = self.buffer.lstrip()
            if self.buffer:
                try:
                    obj, pos = self.decoder.raw_decode(self.buffer)
                except json.JSONDecodeError:
                    pass
                else:
                    self.buffer = self.buffer[pos:]
                    if not isinstance(obj, dict):
                        raise ProtocolError('expected a JSON object')
                    print('Received:', json.dumps(obj), flush=True)
                    if self.observer is not None:
                        self.observer('received', obj)
                    return obj
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ProtocolError('peer closed the connection before a full JSON response')
            self.buffer += chunk.decode('ascii')
            if len(self.buffer) > 1_000_000:
                raise ProtocolError('JSON message too large')


def expect(msg, opcode, type_name=None):
    if msg.get('opcode') == 3:
        raise ProtocolError('peer reported: ' + str(msg.get('error')))
    if msg.get('opcode') != opcode or (type_name is not None and msg.get('type') != type_name):
        raise ProtocolError(f'unexpected reply: {msg}')
    return msg
