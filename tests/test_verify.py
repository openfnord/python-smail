# _*_ coding: utf-8 _*_
import email
import os
import re
from email import message_from_string
from email.policy import default
from tempfile import mkstemp

import pytest

from smail.sign import verify_message
from smail.utils import get_cmd_output, normalize_line_endings
from .conftest import FIXTURE_DIR


class TestVerify:
    @classmethod
    def setup_class(cls):
        """ setup any state specific to the execution of the given class (which
        usually contains tests).
        """

        cls.openssl_binary = os.environ.get("OPENSSL_BINARY", None)
        if not cls.openssl_binary:
            cls.openssl_binary = "openssl"

        cls.message = [
            'From: "Alice" <alice@foo.com>',
            'To: "Carl" <carl@bar.com>',
            "Subject: A message from python",
            "Message-ID: <4231.629.XYzi-What@Other-Host>",
            "Content-Type: text/plain",
            "",
            "Hello,\n"
            "\n"
            "this is a message with line breaks.\n"
            "And some text.\n"
            "\n"
            "Goodbye!",
        ]

    @pytest.mark.parametrize("digest_alg", [
        "sha1",
        "sha256",
        "sha512",
        "sha1",
        "sha256",
        "sha512"
    ])
    def test_message_from_alice(self, digest_alg):
        fd, tmp_file = mkstemp()
        os.write(fd, "\n".join(self.message).encode('ascii'))

        signer_cert = os.path.join(FIXTURE_DIR, 'AliceRSA2048.pem')
        signer_key = os.path.join(FIXTURE_DIR, 'AlicePrivRSA2048.pem')

        # We need to process these as -binary with \r\n newlines,
        # or openssl does some very weird things, duplicating all newlines
        cmd = [
            self.openssl_binary, "smime", "-sign",
            "-md", digest_alg,
            "-in", tmp_file,
            "-signer", signer_cert,
            "-inkey", signer_key
        ]

        # Fix line endings and bypass an OpenSSL windows bug - https://github.com/openssl/openssl/issues/7763
        cmd_output = get_cmd_output(cmd).replace('\r\r\n', '\n').replace('\r\n', '\n')
        signed_message = message_from_string(cmd_output, policy=default)
        checked_message = verify_message(signed_message, signer_cert, prefix="x-")
        payload = checked_message.get_payload().splitlines()

        assert "Goodbye!" in payload[len(payload) - 1]
