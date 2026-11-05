"""Additional Task I: passive eavesdropper on Protocol II (RSA + AES).

Eve is a transparent relay. Alice connects to Eve (believing it is Bob); Eve
forwards every JSON message to the real Bob unchanged and relays Bob's replies
back. Eve never alters the conversation (passive), but copies the public
messages and then breaks the scheme:

    1. n = p*q with p, q in [400, 500], so n < 250000: factor it instantly.
    2. phi = (p-1)(q-1); private key d = e^(-1) mod phi.
    3. RSA-decrypt encrypted_key to rebuild the 32-byte AES key, then
       AES-decrypt both captured messages.

Only works because the parameters are deliberately tiny (toy RSA). Real RSA
uses a 2048-bit modulus that cannot be factored.

Run order:
    python3 bob.py   -p 6000 --message hello
    python3 eve.py   --listen-port 5555 --bob-addr 127.0.0.1 --bob-port 6000
    python3 alice.py -a 127.0.0.1 -p 5555 -t RSA --message world
"""
import argparse
import socket
from crypto_utils import JSONConnection, aes_decrypt, prime_factors, rsa_decrypt_key


def relay(src, dst):
    """Forward one message from src to dst unchanged; return it for inspection."""
    msg = src.recv()
    dst.send(msg)
    return msg


def run(listen_addr, listen_port, bob_addr, bob_port):
    # 1) Wait for Alice (she thinks Eve is Bob)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((listen_addr, listen_port))
    srv.listen(1)
    print(f'[Eve] waiting for Alice on {listen_addr}:{listen_port}', flush=True)
    alice_sock, info = srv.accept()
    print(f'[Eve] Alice connected from {info[0]}:{info[1]}', flush=True)

    # 2) Connect to the real Bob
    bob_sock = socket.create_connection((bob_addr, bob_port), timeout=10)
    print(f'[Eve] connected to the real Bob at {bob_addr}:{bob_port}', flush=True)

    alice = JSONConnection(alice_sock)
    bob = JSONConnection(bob_sock)

    # 3) Relay Protocol II, capturing the public material
    relay(alice, bob)                                   # {opcode:0, type:RSA}
    m = relay(bob, alice)                               # {opcode:1, public:e, parameter:{n}}
    e, n = int(m['public']), int(m['parameter']['n'])
    m = relay(alice, bob)                               # {opcode:2, encrypted_key:[...]}
    encrypted_key = m['encrypted_key']
    m = relay(bob, alice)                               # {opcode:2, type:AES, encryption}
    bob_ct = m['encryption']
    m = relay(alice, bob)                               # {opcode:2, type:AES, encryption}
    alice_ct = m['encryption']

    alice_sock.close()
    bob_sock.close()

    # 4) Break RSA: factor n -> phi -> d -> AES key
    factors = sorted(prime_factors(n))
    p = factors[0]
    q = n // p
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    key = rsa_decrypt_key(encrypted_key, d, n)

    print(f'[Eve] factored n={n} into p={p}, q={q}', flush=True)
    print(f'[Eve] recovered private key d={d}', flush=True)
    print(f'[Eve] recovered {len(key)}-byte AES key', flush=True)

    # 5) Decrypt both captured messages
    print('\n================ EVE: DECRYPTED TRAFFIC ================')
    print(' Bob  -> Alice :', aes_decrypt(key, bob_ct))
    print(' Alice -> Bob  :', aes_decrypt(key, alice_ct))
    print('=======================================================')


def main():
    parser = argparse.ArgumentParser(description='EL2001 Eve passive attacker (Protocol II)')
    parser.add_argument('--listen-addr', default='0.0.0.0', help='where Eve listens for Alice')
    parser.add_argument('--listen-port', type=int, required=True, help='Eve port (Alice connects here)')
    parser.add_argument('--bob-addr', required=True, help='the real Bob address')
    parser.add_argument('--bob-port', type=int, required=True, help='the real Bob port')
    args = parser.parse_args()
    run(args.listen_addr, args.listen_port, args.bob_addr, args.bob_port)


if __name__ == '__main__':
    main()
