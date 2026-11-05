import socket
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


def is_generator(g, p):
    """True if g is a generator (primitive root) of Z_p*.

    g is a generator iff its powers g^1..g^(p-1) mod p hit every value
    in {1, ..., p-1}, i.e. its multiplicative order equals p-1.
    """
    seen = set()
    val = 1
    for _ in range(p - 1):
        val = (val * g) % p
        seen.add(val)
    return len(seen) == p - 1


def derive_dh_key(shared):
    """Turn the DH shared secret (an int) into a 32-byte AES key."""
    two = shared.to_bytes(2, byteorder="big")
    return two * 16


# --- AES helpers (ECB, 256-bit; same scheme as the course examples) ---------


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


# --- Protocol I: RSA key generation + verification --------------------------


def protocol_one(conn):
    send_msg(conn, {"opcode": 0, "type": "RSAKey"})
    rmsg = recv_msg(conn)

    e = rmsg["public"]
    d = rmsg["private"]
    p = rmsg["parameter"]["p"]
    q = rmsg["parameter"]["q"]

    p_ok = is_prime(p)
    q_ok = is_prime(q)
    n = p * q
    phi = (p - 1) * (q - 1)
    range_ok = (400 <= p <= 500) and (400 <= q <= 500)
    key_ok = (gcd(e, phi) == 1) and ((e * d) % phi == 1)
    correct = p_ok and q_ok and range_ok and key_ok

    logging.info("[Alice] p={} (prime={}), q={} (prime={})".format(p, p_ok, q, q_ok))
    logging.info("[Alice] n={}, e(public)={}, d(private)={}".format(n, e, d))
    logging.info("[Alice] >>> RSA keypair is correct: {}".format(correct))


# --- Protocol II: RSA key transport + AES -----------------------------------


def protocol_two(conn, message):
    send_msg(conn, {"opcode": 0, "type": "RSA"})
    rmsg = recv_msg(conn)
    e = rmsg["public"]
    n = rmsg["parameter"]["n"]

    key = random.randbytes(32)
    enc_key = [pow(b, e, n) for b in key]
    send_msg(conn, {"opcode": 2, "type": "RSA", "encrypted_key": enc_key})

    am = recv_msg(conn)
    ct = base64.b64decode(am["encryption"])
    logging.info("[Alice] >>> decrypted from Bob: {}".format(aes_decrypt(key, ct)))

    enc = aes_encrypt(key, message)
    send_msg(
        conn,
        {
            "opcode": 2,
            "type": "AES",
            "encryption": base64.b64encode(enc).decode("ascii"),
        },
    )


# --- Protocol III: DH key exchange + AES ------------------------------------


def protocol_three(conn, message):
    # 1) Request DH; receive Bob's public key and parameters (p, g)
    send_msg(conn, {"opcode": 0, "type": "DH"})
    rmsg = recv_msg(conn)
    B = rmsg["public"]
    p = rmsg["parameter"]["p"]
    g = rmsg["parameter"]["g"]

    # 2) Verify the received prime and generator (Protocol IV error control)
    if not is_prime(p):
        logging.info("[Alice] p={} is NOT prime -> aborting".format(p))
        send_msg(conn, {"opcode": 3, "error": "incorrect prime number"})
        logging.info("[Alice] >>> quit: incorrect prime number")
        return
    if not is_generator(g, p):
        logging.info("[Alice] g={} is NOT a generator mod {} -> aborting".format(g, p))
        send_msg(conn, {"opcode": 3, "error": "incorrect generator"})
        logging.info("[Alice] >>> quit: incorrect generator")
        return
    logging.info("[Alice] p={} (prime=True), g={} (generator=True)".format(p, g))

    # 3) Generate Alice's DH keypair, send her public key
    a = random.randint(2, p - 2)
    A = pow(g, a, p)
    send_msg(conn, {"opcode": 1, "type": "DH", "public": A})

    # 4) Compute the shared secret and derive the AES key
    shared = pow(B, a, p)  # B^a = g^(ab) mod p
    key = derive_dh_key(shared)
    logging.info(
        "[Alice] shared secret={}, derived {}-byte AES key".format(shared, len(key))
    )

    # 5) Receive Bob's AES message, decrypt, print
    am = recv_msg(conn)
    ct = base64.b64decode(am["encryption"])
    logging.info("[Alice] >>> decrypted from Bob: {}".format(aes_decrypt(key, ct)))

    # 6) Encrypt Alice's own message and send it
    enc = aes_encrypt(key, message)
    send_msg(
        conn,
        {
            "opcode": 2,
            "type": "AES",
            "encryption": base64.b64encode(enc).decode("ascii"),
        },
    )


# --- Entry point ------------------------------------------------------------


def run(addr, port, protocol, message):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))

    if protocol == "rsakey":
        protocol_one(conn)
    elif protocol == "rsa":
        protocol_two(conn, message)
    elif protocol == "dh":
        protocol_three(conn, message)

    conn.close()


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--addr",
        metavar="<bob's address>",
        help="Bob's address",
        type=str,
        required=True,
    )
    parser.add_argument(
        "-p",
        "--port",
        metavar="<bob's port>",
        help="Bob's port",
        type=int,
        required=True,
    )
    parser.add_argument(
        "-t",
        "--protocol",
        metavar="<rsakey/rsa/dh>",
        help="Which protocol to run",
        type=str,
        choices=["rsakey", "rsa", "dh"],
        default="rsakey",
    )
    parser.add_argument(
        "-m",
        "--message",
        metavar="<message>",
        help="Message Alice encrypts (Protocol II/III)",
        type=str,
        default="world",
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
    run(args.addr, args.port, args.protocol, args.message)


if __name__ == "__main__":
    main()
