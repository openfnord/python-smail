# _*_ coding: utf-8 _*_
import os
import unittest

from .conftest import FIXTURE_DIR

from smail.cert import Certificate, key_and_certs_from_pkcs12
# from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey
from cryptography.hazmat.backends.openssl.rsa import RSAPrivateKeyWithSerialization


class CertTest(unittest.TestCase):

    def setUp(self):
        self.openssl_binary = os.environ.get("OPENSSL_BINARY", None)
        if not self.openssl_binary:
            self.openssl_binary = "openssl"

    def test_cert_from_pem_file(self):
        cert = Certificate.from_pem_file(os.path.join(FIXTURE_DIR, 'CarlRSASelf.pem'))
        self.assertIsInstance(cert, Certificate)
        self.assertTrue(cert.self_signed)

    def test_cert_from_pem(self):
        with open(os.path.join(FIXTURE_DIR, 'CarlRSASelf.pem'), 'rb') as f:
            cert = Certificate.from_pem(f.read())
            self.assertIsInstance(cert, Certificate)

    def test_cert_from_pem_str_raises_exception(self):
        with open(os.path.join(FIXTURE_DIR, 'CarlRSASelf.pem')) as f:
            with self.assertRaises(TypeError):
                Certificate.from_pem(f.read())

    def test_cert_from_der_file(self):
        cert = Certificate.from_der_file(os.path.join(FIXTURE_DIR, 'google_cert.der'))
        self.assertIsInstance(cert, Certificate)

    def test_cert_from_der(self):
        with open(os.path.join(FIXTURE_DIR, 'google_cert.der'), 'rb') as f:
            cert = Certificate.from_der(f.read())
            self.assertIsInstance(cert, Certificate)

    def test_key_and_certs_from_pkcs12(self):
        with open(os.path.join(FIXTURE_DIR, 'BobRSASignByCarl_password.p12'), 'rb') as f:
            key, cert, certs = key_and_certs_from_pkcs12(f.read(),
                                                         password="password")

        self.assertIsInstance(key, RSAPrivateKeyWithSerialization)
        self.assertIsInstance(cert, Certificate)
        self.assertEqual(len(certs), 1)
        self.assertIsInstance(certs[0], Certificate)
