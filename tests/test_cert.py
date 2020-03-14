# _*_ coding: utf-8 _*_
import os
import unittest

from .conftest import FIXTURE_DIR

from smail.cert import Certificate


class CertTest(unittest.TestCase):

    def setUp(self):
        self.openssl_binary = os.environ.get("OPENSSL_BINARY", None)
        if not self.openssl_binary:
            self.openssl_binary = "openssl"

    def test_cert_from_pem_file(self):
        cert = Certificate.from_pem_file(os.path.join(FIXTURE_DIR, 'CarlRSASelf.pem'))
        self.assertIsInstance(cert, Certificate)
