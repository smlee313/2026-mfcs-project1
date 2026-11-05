# math-project-2026

# Project 1 — Asymmetric Cryptosystem

This project extends the **provided `1/alice.py` and `1/bob.py` TCP skeleton** and uses the JSON/Base64/AES patterns in the provided `1/examples/` folder. The example scripts are preserved under `examples/` for comparison.

The implementation supports RSA key generation and verification, RSA-based encrypted communication, Diffie-Hellman (DH) key exchange, error handling, and an additional **passive attacker (Eve)** that decrypts messages using recorded communication logs.

## Protocol Support

| Protocol | Alice Request | Function |
|---|---|---|
| I | `{"opcode":0,"type":"RSAKey"}` | Bob creates RSA keys; Alice checks primality and `(e*d) % phi == 1` |
| II | `{"opcode":0,"type":"RSA"}` | RSA encrypts each byte of a random 32-byte AES key; both exchange AES-ECB messages in Base64 |
| III | `{"opcode":0,"type":"DH"}` | Validate DH prime and primitive root, perform DH, derive the specified repeated 32-byte AES key, and exchange AES messages |
| IV | Same as III | Alice reports `incorrect prime number` or `incorrect generator` with opcode 3 |
| Additional Task I | Protocol II | Eve factors the RSA modulus to recover the AES key and decrypt messages |
| Additional Task II | Protocol III | Eve solves the small discrete logarithm problem to recover the DH shared secret and decrypt messages |

## Setup

Python 3.9+ recommended. The teacher's examples use `Crypto.Cipher.AES`:

```bash
python -m pip install -r requirements.txt
```

For compatibility, the scripts also support an installed `cryptography` package as a fallback when `pycryptodome` is absent.

## Running — Protocols I, II, and III

Start **Bob first**, in terminal 1:

```bash
python bob.py --port 5555 --message hello
```

Then start Alice in terminal 2. Choose **one**:

```bash
# Protocol I — RSA Key Verification
python alice.py --addr 127.0.0.1 --port 5555 --type RSAKey

# Protocol II — RSA + AES
python alice.py --addr 127.0.0.1 --port 5555 --type RSA --message world

# Protocol III — DH + AES
python alice.py --addr 127.0.0.1 --port 5555 --type DH --message world
```

Bob stays running and accepts further connections. Use `Ctrl+C` to stop.

When Bob runs on another computer, replace `127.0.0.1` with the Bob machine's LAN IP address and check firewall permissions.

## Protocol IV — Error Handling Demo

Stop the usual Bob and restart with **one** bad-parameter setting:

```bash
# Invalid prime
python bob.py --port 5555 --dh-invalid prime

# OR: Invalid generator
python bob.py --port 5555 --dh-invalid generator
```

Then run Alice:

```bash
python alice.py --addr 127.0.0.1 --port 5555 --type DH
```

Alice detects the invalid DH parameter and sends one of the following error messages:

```json
{"opcode":3,"error":"incorrect prime number"}
```

```json
{"opcode":3,"error":"incorrect generator"}
```

Bob displays the received error, and the key exchange is terminated.

## Additional Task — Passive Attacker (Eve)

The additional task implements a passive attacker, Eve, who attempts to decrypt messages exchanged between Alice and Bob.

Instead of intercepting or modifying TCP connections, this implementation uses **communication logs recorded by Bob**.

Alice and Bob communicate directly, while Eve independently analyzes the recorded JSON messages.

### Attack Structure

```text
Alice (Client) <-------- TCP --------> Bob (Server)
                                          |
                                          | Records sent/received JSON
                                          v
                                     capture.jsonl
                                          |
                                          | Reads communication logs
                                          v
                                      Eve (eve.py)
                                          |
                                          v
                                Recover encryption keys
                                          |
                                          v
                               Decrypt "hello" and "world"
```

The communication log contains the transmitted JSON messages, including public cryptographic parameters and ciphertexts. It does not contain the parties' private keys or decrypted plaintexts.

This is an **offline passive cryptanalysis demonstration**, rather than live network packet sniffing.

### Eve Attack Methods

**RSA Attack — Protocol II**

1. Read the RSA public key `(n, e)` from the communication log.
2. Factor the small RSA modulus `n` into `p` and `q`.
3. Calculate `phi = (p-1)*(q-1)`.
4. Recover the RSA private exponent using `d = pow(e, -1, phi)`.
5. Decrypt the RSA-encrypted AES key recorded in the log.
6. Use the recovered AES key to decrypt Alice's and Bob's messages.

**DH Attack — Protocol III**

1. Read the DH public parameters `p`, `g`, and public keys from the log.
2. Solve the discrete logarithm problem by brute force to recover a private exponent.
3. Calculate the DH shared secret using the recovered exponent and the other party's public key.
4. Convert the shared secret into the specified 32-byte AES key.
5. Decrypt Alice's and Bob's AES-encrypted messages.

Both attacks are feasible because the project uses small prime numbers between 400 and 500. These approaches would not be practical against properly configured modern cryptographic systems.

### Running Eve — Three Steps

**Step 1. Start Bob with communication logging enabled.**

Terminal 1:

```bash
python bob.py --port 5555 --message hello --capture capture.jsonl
```

The `--capture` option enables JSON communication logging to `capture.jsonl`.

**Step 2. Run Alice and Bob communication.**

Terminal 2:

For the RSA attack:

```bash
python alice.py --addr 127.0.0.1 --port 5555 --type RSA --message world
```

For the DH attack:

```bash
python alice.py --addr 127.0.0.1 --port 5555 --type DH --message world
```

Alice connects directly to Bob on port `5555`, without passing through Eve.

Both protocol sessions can be recorded in the same `capture.jsonl` file.

**Step 3. Run Eve to analyze the recorded communication.**

Terminal 3:

```bash
python eve.py --capture capture.jsonl
```

Eve reads the communication logs, reconstructs the cryptographic parameters, and attempts to recover the encryption keys.

### Expected Eve Output

A successful attack produces output similar to:

```text
=== RSA ===
[Eve][RSA] Observed public (n, e)
[Eve][RSA] Factored RSA modulus
[Eve][RSA] Recovered AES key

[Eve] Decrypted Bob plaintext: hello
[Eve] Decrypted Alice plaintext: world

=== DH ===
[Eve][DH] Observed DH public parameters
[Eve][DH] Recovered private exponent
[Eve][DH] Recovered shared secret

[Eve] Decrypted Bob plaintext: hello
[Eve] Decrypted Alice plaintext: world
```

The exact RSA/DH parameters and encrypted messages may differ between runs because cryptographic keys are generated using random values.

### Security Demonstration

Eve does not directly receive RSA private keys, DH private exponents, or AES keys.

Instead, Eve reconstructs the required secrets using publicly transmitted information and the mathematical weaknesses of the small parameters used in this educational project.

The successful decryption demonstrates why real-world cryptographic systems require sufficiently large, secure parameters.

## Tests

Run the original protocol tests:

```bash
python -m unittest discover -s tests -v
```

The tests cover RSA key generation, RSA encryption and decryption, DH key exchange, and invalid-parameter handling.

The passive attacker can be tested separately by running Protocol II and III with the `--capture` option and analyzing the resulting log using `eve.py`.

## Project Files
In the version1 directory

| File | Description |
|---|---|
| `alice.py` | Alice client implementation for Protocols I–IV |
| `bob.py` | Bob server implementation and optional communication logging |
| `crypto_utils.py` | RSA, DH, AES, JSON communication, and logging utilities |
| `eve.py` | Passive attacker for RSA and DH cryptanalysis |
| `requirements.txt` | Required Python dependencies |
| `tests/` | Automated protocol tests |
| `examples/` | Original example scripts provided for the project |
| `capture.jsonl` | Communication log generated when capture is enabled |
