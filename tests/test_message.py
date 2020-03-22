# -*- coding: utf-8 -*-
import email
import os
from email.message import Message
from shutil import copyfile

import pytest
from asn1crypto import pem, keys
from asn1crypto.x509 import Certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from smail import sign_message
from smail import encrypt_message
from smail import sign_and_encrypt_message
from tests.conftest import FIXTURE_DIR
from tests.fixtures import get_plain_text_message


class TestMessage:
    """Test Message"""

    test_dir = None
    smtp_host = None
    smtp_port = None
    smtp_user = None
    smtp_pass = None

    @classmethod
    def setup_class(cls):
        """ setup any state specific to the execution of the given class (which
        usually contains tests).
        """

        # use test_output/ as target for output files
        test_base_path = os.path.dirname(os.path.realpath(__file__))
        cls.test_dir = os.path.join(test_base_path, "..", "test_output")

        if not os.path.exists(cls.test_dir):
            os.mkdir(cls.test_dir)
        else:
            # directory exists - remove all files in it
            file_list = [f for f in os.listdir(cls.test_dir)]
            for f in file_list:
                os.remove(os.path.join(cls.test_dir, f))

        try:
            copyfile(os.path.join(FIXTURE_DIR, "BobRSASignByCarl_password.p12"),
                     os.path.join(cls.test_dir, "BobRSASignByCarl_password.p12"))
        except OSError:
            pass

        try:
            copyfile(os.path.join(FIXTURE_DIR, "BobRSASignByCarl_password.txt"),
                     os.path.join(cls.test_dir, "BobRSASignByCarl_password.txt"))
        except OSError:
            pass

        # check and optionally set up mail sending
        cls.smtp_host = os.environ.get("SMAIL_SMTP_HOST", None)
        cls.smtp_port = os.environ.get("SMAIL_SMTP_PORT", None)
        cls.smtp_user = os.environ.get("SMAIL_SMTP_USER", None)
        cls.smtp_pass = os.environ.get("SMAIL_SMTP_PASS", None)

    @classmethod
    def teardown_class(cls):
        """ teardown any state that was previously setup with a call to
        setup_class.
        """

        file_list = [f for f in os.listdir(cls.test_dir)]
        assert set(file_list) == {'BobRSASignByCarl_password.p12',
                                  'BobRSASignByCarl_password.txt',
                                  'plain_message.eml',
                                  'plain_message_encrypted_for_bob.eml',
                                  'plain_message_encrypted_for_bob_3des.eml',
                                  'plain_message_signed_by_alice_md5.eml',
                                  'plain_message_signed_by_alice_sha1.eml',
                                  'plain_message_signed_by_alice_sha256.eml'}

        # (re-)check that everything is a "Message"
        msgs = []
        for f_name in file_list:
            with open(os.path.join(cls.test_dir, f_name), 'rb') as f:
                msg = email.message_from_bytes(f.read())
                assert isinstance(msg, Message)
                msgs.append(msg)

    @pytest.mark.parametrize("output_file_eml", ['plain_message.eml'])
    def test_plain_message(self, output_file_eml):
        file_path = os.path.join(self.test_dir, 'plain_message.eml')

        with open(file_path, 'wb') as f:
            f.write(get_plain_text_message().as_bytes())

    @pytest.mark.parametrize("output_file_eml,pub_key,private_key,hashalgo", [
        ("plain_message_signed_by_alice_md5.eml", "AliceRSASignByCarl.pem", "AlicePrivRSASign.pem", "md5"),
        ("plain_message_signed_by_alice_sha1.eml", "AliceRSASignByCarl.pem", "AlicePrivRSASign.pem", "sha1"),
        ("plain_message_signed_by_alice_sha256.eml", "AliceRSASignByCarl.pem", "AlicePrivRSASign.pem", "sha256")
    ])
    def test_plain_message_signed_by_alice(self, output_file_eml, pub_key, private_key, hashalgo):

        file_path = os.path.join(self.test_dir, output_file_eml)

        with open(os.path.join(FIXTURE_DIR, pub_key), 'rb') as cert_signer_file:
            der_bytes = cert_signer_file.read()
            if pem.detect(der_bytes):
                type_name, headers, der_bytes = pem.unarmor(der_bytes)

            cert_signer = Certificate.load(der_bytes)

        # with open(os.path.join(FIXTURE_DIR, 'AlicePrivRSASign.pem'), 'rb') as key_signer_file:
        #     key_signer = serialization.load_pem_private_key(
        #         key_signer_file.read(),
        #         password=None,
        #         backend=default_backend()
        #     )

        with open(os.path.join(FIXTURE_DIR, private_key), 'rb') as key_signer_file:
            key_bytes = key_signer_file.read()
            if pem.detect(key_bytes):
                _, _, key_bytes = pem.unarmor(key_bytes)

            key_signer = keys.RSAPrivateKey.load(key_bytes)
            key_signer_info = keys.PrivateKeyInfo.load(key_bytes)

        assert isinstance(key_signer_info, keys.PrivateKeyInfo)
        assert isinstance(key_signer, keys.RSAPrivateKey)

        signed_message = sign_message(get_plain_text_message(), key_signer_info, cert_signer, hashalgo=hashalgo)

        assert isinstance(signed_message, email.message.Message)

        with open(file_path, 'wb') as f:
            f.write(signed_message.as_bytes())

    def test_plain_message_encrypted_for_bob(self):
        file_path = os.path.join(self.test_dir, 'plain_message_encrypted_for_bob.eml')

        with open(os.path.join(FIXTURE_DIR, 'BobRSASignByCarl.pem'), 'rb') as cert_file:
            cert = cert_file.read()

        assert isinstance(get_plain_text_message(), email.message.Message)

        encrypted_message = encrypt_message(get_plain_text_message(), certs_recipients=cert)

        with open(file_path, 'wb') as f:
            f.write(encrypted_message.as_bytes())

    def test_plain_message_encrypted_for_bob_3des(self):
        file_path = os.path.join(self.test_dir, 'plain_message_encrypted_for_bob_3des.eml')

        with open(os.path.join(FIXTURE_DIR, 'BobRSASignByCarl.pem'), 'rb') as cert_file:
            cert = cert_file.read()

        encrypted_message = encrypt_message(get_plain_text_message(), certs_recipients=cert, algorithm='tripledes_3key')

        with open(file_path, 'wb') as f:
            f.write(encrypted_message.as_bytes())

    @pytest.mark.skip(reason="not yet updated")
    def test_plain_message_signed_by_alice_encrypted_for_bob(self):
        file_path = os.path.join(self.test_dir, 'plain_message_signed_by_alice_encrypted_for_bob.eml')

        with open(os.path.join(FIXTURE_DIR, 'AliceRSASignByCarl.pem'), 'rb') as cert_signer_file:
            der_bytes = cert_signer_file.read()
            if pem.detect(der_bytes):
                type_name, headers, der_bytes = pem.unarmor(der_bytes)

            cert_signer = Certificate.load(der_bytes)

        with open(os.path.join(FIXTURE_DIR, 'AlicePrivRSASign.pem'), 'rb') as key_signer_file:
            key_signer = serialization.load_pem_private_key(
                key_signer_file.read(),
                password=None,
                backend=default_backend()
            )

        with open(os.path.join(FIXTURE_DIR, 'BobRSASignByCarl.pem'), 'rb') as cert_signer_file:
            der_bytes = cert_signer_file.read()
            if pem.detect(der_bytes):
                type_name, headers, der_bytes = pem.unarmor(der_bytes)

            cert = Certificate.load(der_bytes)

        signed_encrypted_message = sign_and_encrypt_message(get_plain_text_message(),
                                                            cert_signer, key_signer,
                                                            cert)

        with open(file_path, 'wb') as f:
            f.write(signed_encrypted_message.as_bytes())

# @pytest.fixture(params=['plain_message.eml'])
# def plain(request):
#     return request.param
#
#
# class TestMailParam:
#     def test_plain_message(self, plain):
#         assert plain == "plain_message.eml"
#
#     @pytest.mark.parametrize('data', [1, 2, 3, 4])
#     def test_plain_message2(self, data):
#         assert data in range(1, 5)
#
#
# @pytest.mark.parametrize('output_file_eml', ['plain_message.eml'])
# def test_func_plain_message(output_file_eml):
#     assert output_file_eml == "plain_message.eml"
