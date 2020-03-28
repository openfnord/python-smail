# _*_ coding: utf-8 _*_
import email
import os
import re
from email import message_from_string
from tempfile import mkstemp

import pytest
from asn1crypto import keys, pem
from asn1crypto.x509 import Certificate

from .conftest import FIXTURE_DIR
from smail.sign import sign_message
from smail.utils import get_cmd_output


class TestSign:
    @classmethod
    def setup_class(cls):
        """ setup any state specific to the execution of the given class (which
        usually contains tests).
        """

        cls.openssl_binary = os.environ.get("OPENSSL_BINARY", None)
        if not cls.openssl_binary:
            cls.openssl_binary = "openssl"

    @pytest.mark.parametrize("digest_alg,sig_alg,depre", [
        ("sha1", "rsa", True),
        ("sha256", "rsa", False),
        ("sha512", "rsa", False),
        ("sha1", "pss", True),
        ("sha256", "pss", False),
        ("sha512", "pss", False)
    ])
    def test_message_from_alice(self, digest_alg, sig_alg, depre):
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
        assert isinstance(msg, email.message.Message)

        # load cert & key
        with open(os.path.join(FIXTURE_DIR, 'AliceRSA2048.pem'), 'rb') as cert_signer_file:
            der_bytes = cert_signer_file.read()
            if pem.detect(der_bytes):
                type_name, headers, der_bytes = pem.unarmor(der_bytes)

            cert_signer = Certificate.load(der_bytes)

        with open(os.path.join(FIXTURE_DIR, 'AlicePrivRSA2048.pem'), 'rb') as key_signer_file:
            key_bytes = key_signer_file.read()
            if pem.detect(key_bytes):
                _, _, key_bytes = pem.unarmor(key_bytes)

            key_signer_info = keys.PrivateKeyInfo.load(key_bytes)

        msg_signed = sign_message(msg, key_signer_info, cert_signer,
                                  digest_alg=digest_alg, sig_alg=sig_alg,
                                  allow_deprecated=depre)

        fd, tmp_file = mkstemp()
        os.write(fd, msg_signed.as_bytes())

        cmd = [
            self.openssl_binary, "cms", "-verify",
            "-in", tmp_file,
            "-signer", os.path.join(FIXTURE_DIR, 'AliceRSA2048.pem'),
            "-CAfile", os.path.join(FIXTURE_DIR, 'CarlRSA2048Self.pem'),
        ]
        # assert " ".join(cmd) == "foo"
        cmd_output = get_cmd_output(cmd)
        private_message = message_from_string(cmd_output)
        payload = private_message.get_payload().splitlines()

        # assert payload == "foo"
        assert re.compile(r'.*Verification successful.*').search(cmd_output) is not None
        assert "Goodbye!" in payload[len(payload) - 1]
