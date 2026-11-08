"""EL2001 Project 1: Alice (client), built from the supplied skeleton."""
import argparse
import secrets
import socket
from crypto_utils import (
    JSONConnection, ProtocolError, aes_decrypt, aes_encrypt, dh_aes_key,
    dh_keypair, expect, is_generator, is_prime, rsa_encrypt_key,
    verify_rsa_keypair,
)

def protocol_one(peer):
    peer.send({'opcode': 0, 'type': 'RSAKey'})
    response = expect(peer.recv(), 0, 'RSAKey')
    p, q = int(response['parameter']['p']), int(response['parameter']['q'])
    d, e = int(response['private']), int(response['public'])
    print(f'p={p}: prime={is_prime(p)}; q={q}: prime={is_prime(q)}')
    valid = verify_rsa_keypair(p, q, e, d)
    print(f'RSA public key (n,e)=({p*q},{e}); private d={d}; correctness={valid}')
    if not valid:
        raise ProtocolError('incorrect RSA keypair')


def exchange_aes_messages(peer, key, message):
    response = expect(peer.recv(), 2, 'AES')
    print('Bob plaintext:', aes_decrypt(key, response['encryption']))
    peer.send({'opcode': 2, 'type': 'AES', 'encryption': aes_encrypt(key, message)})
    print('Alice plaintext sent:', message)


def protocol_two(peer, message):
    peer.send({'opcode': 0, 'type': 'RSA'})
    response = expect(peer.recv(), 1, 'RSA')
    e = int(response['public'])
    n = int(response['parameter']['n'])
    if not (400 * 400 < n < 500 * 500 and e > 1):
        raise ProtocolError('unexpected RSA public parameters')
    key = secrets.token_bytes(32)
    peer.send({'opcode': 2, 'type': 'RSA', 'encrypted_key': rsa_encrypt_key(key, e, n)})
    exchange_aes_messages(peer, key, message)


def protocol_three(peer, message):
    peer.send({'opcode': 0, 'type': 'DH'})
    response = expect(peer.recv(), 1, 'DH')
    p = int(response['parameter']['p'])
    g = int(response['parameter']['g'])
    if not (400 < p < 500 and is_prime(p)):
        err = 'incorrect prime number'
        peer.send({'opcode': 3, 'error': err})
        print('Error:', err)
        return False
    if not is_generator(g, p):
        err = 'incorrect generator'
        peer.send({'opcode': 3, 'error': err})
        print('Error:', err)
        return False
    bob_public = int(response['public'])
    if not 1 < bob_public < p:
        raise ProtocolError('invalid Bob DH public key')
    private, public = dh_keypair(p, g)
    key = dh_aes_key(pow(bob_public, private, p))
    peer.send({'opcode': 1, 'type': 'DH', 'public': public})
    exchange_aes_messages(peer, key, message)
    return True


def run(addr, port, protocol='RSA', message='world'):
    with socket.create_connection((addr, port), timeout=10) as sock:
        sock.settimeout(10)
        print(f'Alice connected to {addr}:{port}')
        peer = JSONConnection(sock)
        if protocol == 'RSAKey':
            protocol_one(peer)
        elif protocol == 'RSA':
            protocol_two(peer, message)
        elif protocol == 'DH':
            protocol_three(peer, message)
        else:
            raise ProtocolError('unknown protocol')

PORT_TO_TYPE = {5551: 'RSAKey', 5552: 'RSA', 5553: 'DH', 5554: 'DH'}

def main():
    parser = argparse.ArgumentParser(description='EL2001 Alice client')
    parser.add_argument('-a', '--addr', required=True, help='Bob IP / hostname')
    parser.add_argument('-p', '--port', type=int, required=True, help='Bob TCP port')
    parser.add_argument('-t', '--type', choices=['RSAKey', 'RSA', 'DH'], default='RSA', help='Protocol I/II/III')
    parser.add_argument('-m', '--message', default='world', help='Alice AES plaintext (II/III)')
    parser.add_argument('-l', '--log', default='INFO', help='Compatibility with starter code')
    args = parser.parse_args()
    try:
        run(args.addr, args.port, args.type, args.message)
    except (OSError, ProtocolError, KeyError, ValueError) as exc:
        parser.exit(1, f'Alice error: {exc}\n')


if __name__ == '__main__':
    main()
