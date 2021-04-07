# _*_ coding: utf-8 _*_
import os
from email import message_from_string
from email.policy import default
from tempfile import mkstemp

from smail.encrypt import decrypt_message
from smail.utils import get_cmd_output, normalize_line_endings
from .conftest import FIXTURE_DIR


class TestDecrypt:
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

        fd, tmp_file = mkstemp()
        os.write(fd, "\n".join(message).encode())

        cert_recipient = os.path.join(FIXTURE_DIR, 'CarlRSASelf.pem')
        key_recipient = os.path.join(FIXTURE_DIR, 'CarlPrivRSASign.pem')

        cmd = [
            self.openssl_binary, "smime", "-encrypt",
            "-in", tmp_file,
            "-" + algorithm, cert_recipient
        ]

        cmd_output = get_cmd_output(cmd)
        result = decrypt_message(cmd_output, cert_recipient, key_recipient, prefix="x-")
        decrypted_message = message_from_string(result, policy=default)
        payload = decrypted_message.get_payload().splitlines()

        assert "Now you see me." == payload[len(payload) - 1]

    def assert_message_to_bob(self, algorithm):
        message = [
            'From: "Alice" <alice@foo.com>',
            'To: "Bob" <bob@bar.com>',
            "Subject: A message from python for Bob",
            "",
            "Hey Bob, now you see me..!",
        ]

        fd, tmp_file = mkstemp()
        os.write(fd, "\n".join(message).encode())

        cert_recipient = os.path.join(FIXTURE_DIR, 'BobRSASignByCarl.pem')
        key_recipient = os.path.join(FIXTURE_DIR, 'BobPrivRSAEncrypt.pem')

        cmd = [
            self.openssl_binary, "smime", "-encrypt",
            "-in", tmp_file,
            "-" + algorithm, cert_recipient
        ]

        cmd_output = get_cmd_output(cmd)
        result = decrypt_message(cmd_output, cert_recipient, key_recipient, prefix="x-")
        decrypted_message = message_from_string(result, policy=default)
        payload = decrypted_message.get_payload().splitlines()

        assert "Hey Bob, now you see me..!" == payload[len(payload) - 1]

    def test_message_to_bob_tripledes_cbc(self, ):
        self.assert_message_to_bob("des3")

    def test_message_to_carl_tripledes_cbc(self, ):
        self.assert_message_to_carl("des3")

    def test_message_to_carl_aes128_cbc(self):
        self.assert_message_to_carl("aes-128-cbc")

    def test_message_to_carl_aes256_cbc(self, ):
        self.assert_message_to_carl("aes-256-cbc")

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

        fd, tmp_file = mkstemp()
        os.write(fd, "\n".join(message).encode())

        cert_recipient = os.path.join(FIXTURE_DIR, 'CarlRSASelf.pem')
        key_recipient = os.path.join(FIXTURE_DIR, 'CarlPrivRSASign.pem')

        cmd = [
            self.openssl_binary, "smime", "-encrypt",
            "-in", tmp_file,
            "-aes-256-cbc", cert_recipient
        ]

        cmd_output = get_cmd_output(cmd)
        result = decrypt_message(cmd_output, cert_recipient, key_recipient, prefix="x-")
        decrypted_message = message_from_string(result, policy=default)
        payload = normalize_line_endings(decrypted_message.get_payload())

        assert "Hello,\n\nthis is a message with line breaks.\nAnd some text.\n\nGoodbye!" == payload
