# math-project-2026

# Project 1 — Asymmetric Cryptosystem

This solution extends the **provided `1/alice.py` and `1/bob.py` TCP skeleton** and uses the JSON/Base64/AES patterns in the provided `1/examples/` folder. The example scripts are preserved under `examples/` for comparison.

## Protocol support

| Protocol | Alice request | Function |
|---|---|---|
| I | `{"opcode":0,"type":"RSAKey"}` | Bob creates RSA keys; Alice checks primality and `(e*d) % phi == 1` |
| II | `{"opcode":0,"type":"RSA"}` | RSA encrypts each byte of a random 32-byte AES key; both exchange AES-ECB messages in Base64 |
| III | `{"opcode":0,"type":"DH"}` | Validate DH prime and primitive root, perform DH, derive the specified repeated 32-byte AES key, exchange AES messages |
| IV | Same as III | Alice reports `incorrect prime number` or `incorrect generator` with opcode 3 |

## Setup

Python 3.9+ recommended. The teacher's examples use `Crypto.Cipher.AES`:

```bash
python -m pip install -r requirements.txt
```

For compatibility, the new scripts also support an installed `cryptography` package as a fallback when `pycryptodome` is absent.

## Running — two terminals

Start **Bob first**, in terminal 1:

```bash
python bob.py --port 5555 --message hello
```

Then start Alice in terminal 2. Choose **one**:

```bash
python alice.py --addr 127.0.0.1 --port 5555 --type RSAKey
python alice.py --addr 127.0.0.1 --port 5555 --type RSA --message world
python alice.py --addr 127.0.0.1 --port 5555 --type DH --message world
```

Bob stays running and accepts further connections. Use Ctrl+C to stop. When Bob runs on another computer, replace `127.0.0.1` with the Bob machine's LAN IP address and check firewall permissions.

## Protocol IV demo

Stop the usual Bob and restart with *one* bad-parameter setting:

```bash
python bob.py --port 5555 --dh-invalid prime
# OR
python bob.py --port 5555 --dh-invalid generator
```

Then in the other terminal:

```bash
python alice.py --addr 127.0.0.1 --port 5555 --type DH
```

Alice should send the exact `{"opcode":3,"error":"incorrect prime number"}` or `{"opcode":3,"error":"incorrect generator"}` object. Bob displays the received error.

## Test

```bash
python -m unittest discover -s tests -v
```

This tests both normal protocols and error scenarios locally.

## Wire format & compatibility

Messages follow slides 3–16, with `opcode`, `type`, `public`, `parameter`, `encrypted_key`, `encryption`, and `error` as appropriate. The TCP helper accepts complete JSON objects **with or without newline separators** and accounts for messages split across `recv()` calls. It sends each JSON object followed by a newline (valid JSON whitespace). This is a robust replacement for the example's single `recv(1024)` approach.

RSA `public`/`private` are integer exponents, and `n` is derived from primes in protocol I. AES uses PKCS#7 padding, matching the supplied examples. DH secret is turned into a 2-byte big-endian value and repeated 16 times exactly as specified in slide 8.

The slide-15 row for `public` mixes integer and Base64 wording; protocol diagrams and provided `.log` samples use integers, so this implementation uses integers. Confirm the intended public-key serialization with the instructor if their test app requires a different format.

## Security note

This is an educational implementation **only**. Small (~400–500) primes, raw textbook RSA, AES-ECB, and repeated DH shared secrets are insecure in real applications. Do not use it to protect actual secrets.

## Suggested team division and GitHub evidence

- Teammate A: Alice/client, input validation, RSA key verification, DH generator check.
- Teammate B: Bob/server, RSA/DH key generation, AES operations.
- Both: test, debug, review and document each other's features.

Use separate named commits from both contributors, review changes together, and document your real work in this README. Replace these sample responsibilities with your actual division before submitting.

