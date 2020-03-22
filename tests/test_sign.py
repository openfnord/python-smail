# _*_ coding: utf-8 _*_
import email
import os
import unittest
from email import message_from_string
from tempfile import mkstemp

from asn1crypto import keys, pem
from asn1crypto.x509 import Certificate

from .conftest import FIXTURE_DIR
from smail.sign import sign_message
from smail.utils import get_cmd_output


class SignTest(unittest.TestCase):

    def setUp(self):
        self.openssl_binary = os.environ.get("OPENSSL_BINARY", None)
        if not self.openssl_binary:
            self.openssl_binary = "openssl"


    def test_message_from_carl(self):
        message = [
            'From: "Alice" <alice@foo.com>',
            'To: "Carl" <carl@bar.com>',
            "Subject: A message from python",
            "Message-ID: <4231.629.XYzi-What@Other-Host>",
            "",
            "Hello,\n"
            "\n"
            "this is a message with line breaks.\n"
            "And some text.\n"
            "\n"
            "Goodbye!",
        ]

        msg = email.message_from_string("\n".join(message))
        self.assertIsInstance(msg, email.message.Message)

        # load cert & key
        with open(os.path.join(FIXTURE_DIR, 'CarlRSASelf.pem'), 'rb') as cert_signer_file:
            der_bytes = cert_signer_file.read()
            if pem.detect(der_bytes):
                type_name, headers, der_bytes = pem.unarmor(der_bytes)

            cert_signer = Certificate.load(der_bytes)

        with open(os.path.join(FIXTURE_DIR, 'CarlPrivRSASign.pem'), 'rb') as key_signer_file:
            key_bytes = key_signer_file.read()
            if pem.detect(key_bytes):
                _, _, key_bytes = pem.unarmor(key_bytes)

            key_signer_info = keys.PrivateKeyInfo.load(key_bytes)

        msg_signed = sign_message(msg, key_signer_info, cert_signer, other_certs=[], hashalgo='sha256')

        fd, tmp_file = mkstemp()
        os.write(fd, msg_signed.as_bytes())

        cmd = [
            self.openssl_binary, "smime", "-verify",
            "-in", tmp_file,
            "-signer", os.path.join(FIXTURE_DIR, 'CarlRSASelf.pem'),
            "-CAfile", os.path.join(FIXTURE_DIR, 'CarlRSASelf.pem'),
        ]
        # assert " ".join(cmd) == "foo"
        cmd_output = get_cmd_output(cmd)
        private_message = message_from_string(cmd_output)
        payload = private_message.get_payload().splitlines()

        self.assertIn("Verification successful", payload)
        self.assertEqual("Goodbye!", payload[len(payload) - 1])
