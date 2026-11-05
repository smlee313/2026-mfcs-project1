"""EL2001 Project 1: Bob (server), built from supplied threading skeleton."""
import argparse
import socket
import secrets
import threading
from crypto_utils import (
    JSONConnection, ProtocolError, aes_decrypt, aes_encrypt, dh_aes_key,
    dh_keypair, expect, generate_rsa_keypair, is_generator, is_prime,
    random_prime, rsa_decrypt_key,
)


def protocol_one(peer):
    key = generate_rsa_keypair()
    peer.send({'opcode': 0, 'type': 'RSAKey', 'private': key['d'],
               'public': key['e'], 'parameter': {'p': key['p'], 'q': key['q']}})
    print('RSA keypair generated')


def protocol_two(peer, message):
    key = generate_rsa_keypair()
    peer.send({'opcode': 1, 'type': 'RSA', 'public': key['e'],
               'parameter': {'n': key['n']}})
    response = expect(peer.recv(), 2, 'RSA')
    aes_key = rsa_decrypt_key(response['encrypted_key'], key['d'], key['n'])
    peer.send({'opcode': 2, 'type': 'AES', 'encryption': aes_encrypt(aes_key, message)})
    response = expect(peer.recv(), 2, 'AES')
    print('Alice plaintext:', aes_decrypt(aes_key, response['encryption']))


def protocol_three(peer, message, invalid='none'):
    p = random_prime()
    while p == 499 and invalid == 'prime':
        p = random_prime()
    generators = [x for x in range(2, p) if is_generator(x, p)]
    g = secrets.choice(generators)
    if invalid == 'prime':
        p = 400  # deliberately composite, for Protocol IV-I test
    elif invalid == 'generator':
        g = 1  # definitely not a generator, for Protocol IV-II test
    private, public = dh_keypair(p, g)
    peer.send({'opcode': 1, 'type': 'DH', 'public': public, 'parameter': {'p': p, 'g': g}})
    response = peer.recv()
    if response.get('opcode') == 3:
        print('Alice rejected DH parameters:', response.get('error'))
        return
    expect(response, 1, 'DH')
    alice_public = int(response['public'])
    if not (1 < alice_public < p):
        raise ProtocolError('invalid Alice DH public key')
    aes_key = dh_aes_key(pow(alice_public, private, p))
    peer.send({'opcode': 2, 'type': 'AES', 'encryption': aes_encrypt(aes_key, message)})
    response = expect(peer.recv(), 2, 'AES')
    print('Alice plaintext:', aes_decrypt(aes_key, response['encryption']))


def handler(sock, message='hello', invalid='none'):
    with sock:
        sock.settimeout(10)
        peer = JSONConnection(sock)
        try:
            request = peer.recv()
            expect(request, 0)
            typ = request.get('type')
            if typ == 'RSAKey':
                protocol_one(peer)
            elif typ == 'RSA':
                protocol_two(peer, message)
            elif typ == 'DH':
                protocol_three(peer, message, invalid)
            else:
                raise ProtocolError('unsupported protocol type: ' + str(typ))
        except (OSError, ValueError, KeyError, ProtocolError) as exc:
            print('Bob handler error:', exc, flush=True)


def run(addr, port, message='hello', invalid='none'):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bob:
        bob.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bob.bind((addr, port))
        bob.listen(10)
        print(f'Bob listening on {addr}:{port}', flush=True)
        while True:
            conn, info = bob.accept()
            print(f'Bob accepted {info}', flush=True)
            threading.Thread(target=handler, args=(conn, message, invalid), daemon=True).start()


def main():
    parser = argparse.ArgumentParser(description='EL2001 Bob server')
    parser.add_argument('-a', '--addr', default='0.0.0.0', help='Bind address')
    parser.add_argument('-p', '--port', type=int, required=True, help='TCP port')
    parser.add_argument('-m', '--message', default='hello', help='Bob AES plaintext')
    parser.add_argument('--dh-invalid', choices=['none', 'prime', 'generator'], default='none',
                        help='For Protocol IV error-handling demo only')
    parser.add_argument('-l', '--log', default='INFO', help='Compatibility with starter code')
    args = parser.parse_args()
    try:
        run(args.addr, args.port, args.message, args.dh_invalid)
    except OSError as exc:
        parser.exit(1, f'Bob error: {exc}\n')


if __name__ == '__main__':
    main()
