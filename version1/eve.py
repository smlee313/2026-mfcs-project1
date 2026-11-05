"""Additional Task I (offline): passive eavesdropper on a CAPTURED Protocol II log.

The purest form of a passive attack: Eve never connects to anyone. She is only
given the recorded messages that Alice and Bob exchanged (one JSON object per
line, e.g. adv_protocol_two.log) and recovers the plaintext from them alone.

    python3 eve_offline.py adv_protocol_two.log

Why it works: n = p*q with p, q in [400, 500], so n < 250000 factors instantly,
which hands Eve the RSA private key and then the AES key. Real RSA (2048-bit n)
is immune.
"""
import argparse
import json
from crypto_utils import prime_factors, rsa_decrypt_key, aes_decrypt


def load_messages(path):
    """Read a capture file of one JSON object per line."""
    messages = []
    with open(path, encoding="ascii") as fh:
        for line in fh:
            line = line.strip()
            if line:
                messages.append(json.loads(line))
    return messages


def run(path):
    messages = load_messages(path)

    e = n = None
    encrypted_key = None
    ciphertexts = []
    for m in messages:
        if m.get("type") == "RSA" and "parameter" in m and "n" in m["parameter"]:
            e, n = int(m["public"]), int(m["parameter"]["n"])      # Bob's public key
        elif m.get("type") == "RSA" and "encrypted_key" in m:
            encrypted_key = m["encrypted_key"]                     # RSA-wrapped AES key
        elif m.get("type") == "AES":
            ciphertexts.append(m["encryption"])                    # AES messages

    if e is None or encrypted_key is None:
        raise SystemExit("capture is missing the RSA public key or the encrypted AES key")

    # Break RSA: factor n -> phi -> private key d -> AES key
    p = sorted(prime_factors(n))[0]
    q = n // p
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    key = rsa_decrypt_key(encrypted_key, d, n)

    print(f"[Eve] n={n} factored into p={p}, q={q}")
    print(f"[Eve] recovered private key d={d}")
    print(f"[Eve] recovered {len(key)}-byte AES key")
    print("\n================ EVE: DECRYPTED TRAFFIC ================")
    for i, ct in enumerate(ciphertexts, 1):
        print(f" message {i}: {aes_decrypt(key, ct)}")
    print("=======================================================")


def main():
    parser = argparse.ArgumentParser(description="Eve offline attacker (Protocol II capture)")
    parser.add_argument("logfile", help="captured message log (one JSON object per line)")
    args = parser.parse_args()
    run(args.logfile)


if __name__ == "__main__":
    main()