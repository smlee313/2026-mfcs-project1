import contextlib
import io
import socket
import threading
import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import alice
import bob
from crypto_utils import (aes_decrypt, aes_encrypt, dh_aes_key, generate_rsa_keypair,
                          is_generator, is_prime, rsa_decrypt_key, rsa_encrypt_key,
                          verify_rsa_keypair)


class CryptoMathTest(unittest.TestCase):
    def test_rsa(self):
        for _ in range(5):
            k = generate_rsa_keypair()
            self.assertTrue(verify_rsa_keypair(k['p'], k['q'], k['e'], k['d']))
            plain = bytes(range(32))
            self.assertEqual(rsa_decrypt_key(rsa_encrypt_key(plain, k['e'], k['n']), k['d'], k['n']), plain)

    def test_generator(self):
        self.assertTrue(is_prime(401))
        self.assertFalse(is_prime(400))
        self.assertTrue(any(is_generator(g, 401) for g in range(2, 401)))
        self.assertFalse(is_generator(1, 401))

    def test_aes(self):
        key = dh_aes_key(298)
        self.assertEqual(len(key), 32)
        for msg in ('hello', '', '한글 테스트 🎯', 'x'*1000):
            self.assertEqual(aes_decrypt(key, aes_encrypt(key, msg)), msg)


class IntegrationTest(unittest.TestCase):
    def exercise(self, protocol, invalid='none'):
        ready = threading.Event()
        result = {}
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def server():
            try:
                ready.set()
                conn, _ = listener.accept()
                bob.handler(conn, 'hello', invalid)
            except Exception as exc:
                result['exception'] = exc
            finally:
                listener.close()

        th = threading.Thread(target=server)
        # Redirect stdout once around both threads; redirect_stdout within
        # separate threads would change sys.stdout globally and lose output.
        with contextlib.redirect_stdout(io.StringIO()) as out:
            th.start()
            ready.wait(timeout=5)
            alice.run('127.0.0.1', port, protocol, 'world')
            th.join(timeout=5)
            output = out.getvalue()
        self.assertFalse(th.is_alive())
        self.assertNotIn('exception', result)
        self.assertNotIn('handler error', output)
        return output

    def test_protocol_i(self):
        self.assertIn('correctness=True', self.exercise('RSAKey'))

    def test_protocol_ii(self):
        output = self.exercise('RSA')
        self.assertIn('Bob plaintext: hello', output)
        self.assertIn('Alice plaintext: world', output)

    def test_protocol_iii(self):
        output = self.exercise('DH')
        self.assertIn('Bob plaintext: hello', output)
        self.assertIn('Alice plaintext: world', output)

    def test_invalid_prime(self):
        output = self.exercise('DH', 'prime')
        self.assertIn('incorrect prime number', output)

    def test_invalid_generator(self):
        output = self.exercise('DH', 'generator')
        self.assertIn('incorrect generator', output)


if __name__ == '__main__':
    unittest.main()
