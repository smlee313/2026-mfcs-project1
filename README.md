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





