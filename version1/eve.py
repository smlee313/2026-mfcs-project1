"""EL2001 Project 1 - offline PASSIVE Eve.

Reads only JSON messages written from Bob's wire activity. Never connects to
Alice/Bob, alters packets or receives either party's private keys.
This is an intentionally weak classroom cryptosystem (400 < primes < 500).
"""
import argparse
import json
from collections import defaultdict
from pathlib import Path
from crypto_utils import aes_decrypt, dh_aes_key, is_prime, rsa_decrypt_key


def factor_semiprime(n):
    """Recover the two small prime factors of n = p*q by trial division."""
    for p in range(2, int(n ** 0.5) + 1):
        if n % p == 0:
            q = n // p
            if is_prime(p) and is_prime(q):
                return p, q
    raise ValueError('Cannot factor n into two primes')


def discrete_log(g, target, p):
    """Find x such that g^x mod p = target; feasible only for small p."""
    current = 1
    for x in range(p):
        if current == target:
            return x
        current = (current * g) % p
    raise ValueError('Could not recover DH exponent')


def find_msg(items, direction, typ, opcode):
    for row in items:
        msg = row['message']
        if (row['direction'] == direction and msg.get('type') == typ
                and msg.get('opcode') == opcode):
            return msg
    raise ValueError(f'Missing message: {direction}, {typ}, opcode={opcode}')


def decrypt_aes_messages(items, key):
    for row in items:
        msg = row['message']
        if msg.get('type') != 'AES' or msg.get('opcode') != 2:
            continue
        source = 'Bob' if row['direction'] == 'Bob->Alice' else 'Alice'
        print(f'[Eve] Decrypted {source} plaintext: {aes_decrypt(key, msg["encryption"])}')


def analyze_rsa(items):
    first = find_msg(items, 'Bob->Alice', 'RSA', 1)
    n, e = int(first['parameter']['n']), int(first['public'])
    p, q = factor_semiprime(n)
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    print(f'[Eve][RSA] Observed public (n, e)=({n}, {e})')
    print(f'[Eve][RSA] Factored n into p={p}, q={q}; computed private exponent d={d}')
    encrypted = find_msg(items, 'Alice->Bob', 'RSA', 2)['encrypted_key']
    key = rsa_decrypt_key(encrypted, d, n)
    print('[Eve][RSA] Recovered AES key from 32 encrypted bytes')
    decrypt_aes_messages(items, key)


def analyze_dh(items):
    bob = find_msg(items, 'Bob->Alice', 'DH', 1)
    alice = find_msg(items, 'Alice->Bob', 'DH', 1)
    p, g = int(bob['parameter']['p']), int(bob['parameter']['g'])
    a_public, b_public = int(alice['public']), int(bob['public'])
    alice_private = discrete_log(g, a_public, p)
    secret = pow(b_public, alice_private, p)
    key = dh_aes_key(secret)
    print(f'[Eve][DH] Observed p={p}, g={g}, Alice public={a_public}, Bob public={b_public}')
    print(f'[Eve][DH] Found Alice exponent a={alice_private} using discrete-log search')
    print(f'[Eve][DH] Recovered shared secret={secret}; derived AES key')
    decrypt_aes_messages(items, key)


def analyze_file(path):
    sessions = defaultdict(list)
    with open(path, encoding='utf-8') as f:
        for line_number, line in enumerate(f, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not {'session', 'direction', 'message'} <= row.keys():
                raise ValueError(f'Invalid JSONL record at line {line_number}')
            sessions[str(row['session'])].append(row)
    if not sessions:
        raise ValueError('Empty capture log. First run Alice and Bob with --capture.')
    results = 0
    for session, rows in sessions.items():
        initial = rows[0]['message']
        typ = initial.get('type')
        print(f'\n=== Session {session} | {typ} ===')
        if typ not in ('RSA', 'DH'):
            print('[Eve] Skipping non-RSA/DH session')
            continue
        if any(row['message'].get('opcode') == 3 for row in rows):
            print('[Eve] Error response in this session; no encrypted messages to decrypt')
            continue
        try:
            if typ == 'RSA':
                analyze_rsa(rows)
            else:
                analyze_dh(rows)
            results += 1
        except (KeyError, ValueError, TypeError, OverflowError) as exc:
            print(f'[Eve] Incomplete or invalid captured session: {exc}')
    print(f'\n[Eve] Successfully analyzed {results} session(s).')
    return results


def main():
    parser = argparse.ArgumentParser(description='Offline passive Eve: read only recorded Alice/Bob JSON messages')
    parser.add_argument('--capture', required=True, type=Path, help='Path to Bob captured JSONL file')
    args = parser.parse_args()
    try:
        analyze_file(args.capture)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.exit(1, f'Eve error: {exc}\n')


if __name__ == '__main__':
    main()
