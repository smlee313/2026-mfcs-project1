import socket
import threading
import argparse
import logging
import json
import random
import base64
from Crypto.Cipher import AES

BLOCK_SIZE = 16

# --- Math helpers -----------------------------------------------------------


def is_prime(n):
    """Trial-division primality test (fine for small numbers)."""
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)


def modinv(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("no modular inverse for {} mod {}".format(a, m))
    return x % m


def gen_prime(low, high):
    while True:
        c = random.randint(low, high)
        if is_prime(c):
            return c


def gen_composite(low, high):
    """Pick a random NON-prime in [low, high] (used to demo Protocol IV-I)."""
    while True:
        c = random.randint(low, high)
        if not is_prime(c):
            return c


def is_generator(g, p):
    """True if g is a generator (primitive root) of Z_p*."""
    seen = set()
    val = 1
    for _ in range(p - 1):
        val = (val * g) % p
        seen.add(val)
    return len(seen) == p - 1


def find_generator(p):
    """Find a (random) generator of Z_p*."""
    while True:
        g = random.randint(2, p - 1)
        if is_generator(g, p):
            return g


def find_non_generator(p):
    """Find a value in [2, p-1] that is NOT a generator (used to demo Protocol IV-II)."""
    while True:
        g = random.randint(2, p - 1)
        if not is_generator(g, p):
            return g


# --- RSA key generation -----------------------------------------------------


def generate_rsa_keypair():
    p = gen_prime(400, 500)
    q = gen_prime(400, 500)
    while q == p:
        q = gen_prime(400, 500)
    n = p * q
    phi = (p - 1) * (q - 1)
    while True:
        e = random.randint(3, phi - 1)
        if gcd(e, phi) == 1:
            break
    d = modinv(e, phi)
    return p, q, n, e, d


# --- DH key generation + shared-secret key derivation -----------------------


def generate_dh_keypair():
    p = gen_prime(400, 500)
    g = find_generator(p)
    secret = random.randint(2, p - 2)
    public = pow(g, secret, p)
    return p, g, secret, public


def derive_dh_key(shared):
    two = shared.to_bytes(2, byteorder="big")
    return two * 16


# --- AES helpers ------------------------------------------------------------


def aes_encrypt(key, msg):
    data = msg.encode("ascii")
    padlen = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    data = data + bytes([padlen]) * padlen
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(data)


def aes_decrypt(key, ct):
    aes = AES.new(key, AES.MODE_ECB)
    pt = aes.decrypt(ct)
    return pt[: -pt[-1]].decode("ascii")


# --- Message send/recv ------------------------------------------------------


def send_msg(conn, obj):
    conn.send(json.dumps(obj).encode("ascii"))
    logging.info("[*] Sent: {}".format(obj))


def recv_msg(conn):
    rbytes = conn.recv(4096)
    if not rbytes:
        return None
    rmsg = json.loads(rbytes.decode("ascii"))
    logging.info("[*] Received: {}".format(rmsg))
    return rmsg


# --- Protocol I: RSA key generation -----------------------------------------


def handle_rsakey(conn, req):
    p, q, n, e, d = generate_rsa_keypair()
    logging.info("[Bob] generated p={}, q={}, n={}, e={}, d={}".format(p, q, n, e, d))
    send_msg(
        conn,
        {
            "opcode": 0,
            "type": "RSAKey",
            "private": d,
            "public": e,
            "parameter": {"p": p, "q": q},
        },
    )


# --- Protocol II: RSA key transport + AES -----------------------------------


def handle_rsa(conn, req, message):
    p, q, n, e, d = generate_rsa_keypair()
    logging.info("[Bob] RSA keypair: n={}, e={}, d={}".format(n, e, d))
    send_msg(conn, {"opcode": 1, "type": "RSA", "public": e, "parameter": {"n": n}})

    km = recv_msg(conn)
    enc_key = km["encrypted_key"]
    key = bytes([pow(c, d, n) for c in enc_key])
    logging.info("[Bob] recovered {}-byte AES key".format(len(key)))

    enc = aes_encrypt(key, message)
    send_msg(
        conn,
        {
            "opcode": 2,
            "type": "AES",
            "encryption": base64.b64encode(enc).decode("ascii"),
        },
    )

    am = recv_msg(conn)
    ct = base64.b64decode(am["encryption"])
    logging.info("[Bob] >>> decrypted from Alice: {}".format(aes_decrypt(key, ct)))


# --- Protocol III (normal) + Protocol IV (error demo) -----------------------


def handle_dh(conn, req, message, bad):
    # Generate a real DH keypair
    p, g, b, B = generate_dh_keypair()

    # For the Protocol IV demo, optionally corrupt the parameters we SEND.
    send_p, send_g = p, g
    if bad == "prime":
        send_p = gen_composite(400, 500)  # Protocol IV-I: non-prime
        logging.info("[Bob] (IV demo) sending a NON-PRIME p={}".format(send_p))
    elif bad == "generator":
        send_g = find_non_generator(p)  # Protocol IV-II: non-generator
        logging.info("[Bob] (IV demo) sending a NON-GENERATOR g={}".format(send_g))

    logging.info("[Bob] DH: p={}, g={}, secret b={}, public B={}".format(p, g, b, B))
    send_msg(
        conn,
        {
            "opcode": 1,
            "type": "DH",
            "public": B,
            "parameter": {"p": send_p, "g": send_g},
        },
    )

    # Receive Alice's reply: either her public key, or an error (opcode 3)
    reply = recv_msg(conn)
    if reply is None:
        return
    if reply.get("opcode") == 3:
        logging.info(
            "[Bob] >>> received error from Alice: {}".format(reply.get("error"))
        )
        return

    # Normal Protocol III: compute shared secret and exchange AES messages
    A = reply["public"]
    shared = pow(A, b, p)
    key = derive_dh_key(shared)
    logging.info(
        "[Bob] shared secret={}, derived {}-byte AES key".format(shared, len(key))
    )

    enc = aes_encrypt(key, message)
    send_msg(
        conn,
        {
            "opcode": 2,
            "type": "AES",
            "encryption": base64.b64encode(enc).decode("ascii"),
        },
    )

    am2 = recv_msg(conn)
    ct = base64.b64decode(am2["encryption"])
    logging.info("[Bob] >>> decrypted from Alice: {}".format(aes_decrypt(key, ct)))


# --- Dispatch ---------------------------------------------------------------


def handler(conn, message, bad):
    req = recv_msg(conn)
    if req is None:
        logging.warning("[Bob] empty connection, closing")
        conn.close()
        return

    msg_type = req.get("type")
    if msg_type == "RSAKey":
        handle_rsakey(conn, req)
    elif msg_type == "RSA":
        handle_rsa(conn, req, message)
    elif msg_type == "DH":
        handle_dh(conn, req, message, bad)
    else:
        logging.error("[Bob] unknown type: {}".format(msg_type))

    conn.close()


def run(addr, port, message, bad):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))
    bob.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(addr, port))

    while True:
        conn, info = bob.accept()
        logging.info(
            "[*] Bob accepts the connection from {}:{}".format(info[0], info[1])
        )
        conn_handle = threading.Thread(target=handler, args=(conn, message, bad))
        conn_handle.start()
        conn_handle.join()


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--addr",
        metavar="<bob's IP address>",
        help="Bob's IP address",
        type=str,
        default="0.0.0.0",
    )
    parser.add_argument(
        "-p",
        "--port",
        metavar="<bob's open port>",
        help="Bob's port",
        type=int,
        required=True,
    )
    parser.add_argument(
        "-m",
        "--message",
        metavar="<message>",
        help="Message Bob encrypts (Protocol II/III)",
        type=str,
        default="hello",
    )
    parser.add_argument(
        "-b",
        "--bad",
        metavar="<none/prime/generator>",
        help="DH demo: send a bad prime or generator (Protocol IV)",
        type=str,
        choices=["none", "prime", "generator"],
        default="none",
    )
    parser.add_argument(
        "-l",
        "--log",
        metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>",
        help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)",
        type=str,
        default="INFO",
    )
    args = parser.parse_args()
    return args


def main():
    args = command_line_args()
    logging.basicConfig(level=args.log)
    run(args.addr, args.port, args.message, args.bad)


if __name__ == "__main__":
    main()
