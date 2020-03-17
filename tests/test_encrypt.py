# _*_ coding: utf-8 _*_
import os
import unittest
from email import message_from_string
from tempfile import mkstemp

from .conftest import FIXTURE_DIR
from smail.encrypt import encrypt_message
from smail.cmd_util import get_cmd_output


class EncryptTest(unittest.TestCase):

    def setUp(self):
        self.openssl_binary = os.environ.get("OPENSSL_BINARY", None)
        if not self.openssl_binary:
            self.openssl_binary = "openssl"

    def assert_message_to_carl(self, algorithm):
        message = [
            'From: "Alice" <alice@foo.com>',
            'To: "Carl" <carl@bar.com>',
            "Subject: A message from python",
            "",
            "Now you see me.",
        ]

        with open(os.path.join(FIXTURE_DIR, 'CarlRSASelf.pem'), 'rb') as cert:
            result = encrypt_message("\n".join(message), cert.read(), algorithm=algorithm)

        fd, tmp_file = mkstemp()
        os.write(fd, result.encode())

        cmd = [
            self.openssl_binary, "smime", "-decrypt",
            "-in", tmp_file,
            "-inkey", os.path.join(FIXTURE_DIR, 'CarlPrivRSASign.pem'),
        ]
        cmd_output = get_cmd_output(cmd)
        private_message = message_from_string(cmd_output)
        payload = private_message.get_payload().splitlines()

        self.assertEqual("Now you see me.", payload[len(payload) - 1])

    def test_message_to_carl_aes256_cbc(self, ):
        self.assert_message_to_carl("aes256_cbc")

    def test_message_to_carl_aes192_cbc(self):
        self.assert_message_to_carl("aes192_cbc")

    def test_message_to_carl_aes128_cbc(self):
        self.assert_message_to_carl("aes128_cbc")

    def test_message_with_breaks_to_carl_aes256_cbc(self):
        message = [
            'From: "Alice" <alice@foo.com>',
            'To: "Carl" <carl@bar.com>',
            "Subject: A message from python",
            "",
            "Hello,\n"
            "\n"
            "this is a message with line breaks.\n"
            "And some text.\n"
            "\n"
            "Goodbye!",
        ]
        with open(os.path.join(FIXTURE_DIR, 'CarlRSASelf.pem'), 'rb') as cert:
            result = encrypt_message("\n".join(message), cert.read(), algorithm="aes256_cbc")

        fd, tmp_file = mkstemp()
        os.write(fd, result.encode())

        cmd = [
            self.openssl_binary, "smime", "-decrypt",
            "-in", tmp_file,
            "-inkey", os.path.join(FIXTURE_DIR, 'CarlPrivRSASign.pem'),
        ]
        cmd_output = get_cmd_output(cmd)
        private_message = message_from_string(cmd_output)

        self.assertEqual(("Hello,\n"
                          "\n"
                          "this is a message with line breaks.\n"
                          "And some text.\n"
                          "\n"
                          "Goodbye!"), private_message.get_payload())
