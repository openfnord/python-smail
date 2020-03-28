# _*_ coding: utf-8 _*_
import os
from email import message_from_string
from tempfile import mkstemp

import pytest

from .conftest import FIXTURE_DIR
from smail.encrypt import encrypt_message
from smail.utils import get_cmd_output, normalize_line_endings


class EncryptTest:
    @classmethod
    def setup_class(cls):
        """ setup any state specific to the execution of the given class (which
        usually contains tests).
        """

        cls.openssl_binary = os.environ.get("OPENSSL_BINARY", None)
        if not cls.openssl_binary:
            cls.openssl_binary = "openssl"

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

        # cert = asymmetric.load_certificate(os.path.join(FIXTURE_DIR, 'CarlRSASelf.pem'))
        # result = encrypt_message("\n".join(message), [cert], algorithm=algorithm)

        fd, tmp_file = mkstemp()
        os.write(fd, result.encode())

        cmd = [
            self.openssl_binary, "smime", "-decrypt",
            "-in", tmp_file,
            "-inkey", os.path.join(FIXTURE_DIR, 'CarlPrivRSASign.pem'),
        ]

        # self.assertEqual(" ".join(cmd), "foo")

        cmd_output = get_cmd_output(cmd)
        private_message = message_from_string(cmd_output)
        payload = private_message.get_payload().splitlines()

        assert "Now you see me." == payload[len(payload) - 1]

    def assert_message_to_bob(self, algorithm):
        message = [
            'From: "Alice" <alice@foo.com>',
            'To: "Bob" <bob@bar.com>',
            "Subject: A message from python for Bob",
            "",
            "Hey Bob, now you see me..!",
        ]

        with open(os.path.join(FIXTURE_DIR, 'BobRSASignByCarl.pem'), 'rb') as cert:
            result = encrypt_message("\n".join(message), cert.read(), algorithm=algorithm)

        fd, tmp_file = mkstemp()
        os.write(fd, result.encode())

        cmd = [
            self.openssl_binary, "smime", "-decrypt",
            "-in", tmp_file,
            "-inkey", os.path.join(FIXTURE_DIR, 'BobPrivRSAEncrypt.pem'),
        ]

        # self.assertEqual(" ".join(cmd), "foo")

        cmd_output = get_cmd_output(cmd)
        private_message = message_from_string(cmd_output)
        payload = private_message.get_payload().splitlines()

        assert "Hey Bob, now you see me..!" == payload[len(payload) - 1]

    @pytest.mark.skip
    def test_message_to_bob_tripleDES_cbc(self, ):
        self.assert_message_to_bob("tripledes_3key")

    def test_message_to_carl_tripleDES_cbc(self, ):
        self.assert_message_to_carl("tripledes_3key")

    def test_message_to_carl_aes128_cbc(self):
        self.assert_message_to_carl("aes128_cbc")

    def test_message_to_carl_aes256_cbc(self, ):
        self.assert_message_to_carl("aes256_cbc")

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
            result = encrypt_message("\n".join(message), cert.read())

        fd, tmp_file = mkstemp()
        os.write(fd, result.encode())

        cmd = [
            self.openssl_binary, "smime", "-decrypt",
            "-in", tmp_file,
            "-inkey", os.path.join(FIXTURE_DIR, 'CarlPrivRSASign.pem'),
        ]
        cmd_output = get_cmd_output(cmd)
        private_message = message_from_string(cmd_output)

        result = normalize_line_endings(private_message.get_payload())

        assert "Hello,\n\nthis is a message with line breaks.\nAnd some text.\n\nGoodbye!" == result
