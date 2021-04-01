# -*- coding: utf-8 -*-
import email
import os
from email.message import Message
from shutil import copyfile

import pytest
from asn1crypto import pem, keys, x509

from smail import encrypt_message
from smail import sign_and_encrypt_message
from smail import sign_message
from smail.message import make_msg
from tests.conftest import FIXTURE_DIR
from tests.fixtures import get_plain_text_message, get_message


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
                                  'msg_w1_att_message_encrypted_for_bob_aes256_cbc.eml',
                                  'msg_w2_att_message_encrypted_for_bob_aes256_cbc.eml',
                                  'plain_message.eml',
                                  'plain_message_encrypted_for_alice_and_bob_aes256_cbc.eml',
                                  'plain_message_encrypted_for_bob_aes128_cbc.eml',
                                  'plain_message_encrypted_for_bob_aes256_cbc.eml',
                                  'plain_message_encrypted_for_bob_tripledes.eml',
                                  'plain_message_signed_by_alice_encrypted_for_bob.eml',
                                  'plain_message_signed_by_alice_md5.eml',
                                  'plain_message_signed_by_alice_sha1.eml',
                                  'plain_message_signed_by_alice_sha1_pss.eml',
                                  'plain_message_signed_by_alice_sha256.eml',
                                  'plain_message_signed_by_alice_sha256_incl_false_false.eml',
                                  'plain_message_signed_by_alice_sha256_incl_false_true.eml',
                                  'plain_message_signed_by_alice_sha256_incl_true_false.eml',
                                  'plain_message_signed_by_alice_sha256_incl_true_true.eml',
                                  'plain_message_signed_by_alice_sha256_pss.eml'}

        # (re-)check that everything is a "Message"
        msgs = []
        for f_name in file_list:
            with open(os.path.join(cls.test_dir, f_name), 'rb') as f:
                msg = email.message_from_bytes(f.read(), policy=email.policy.default)
                assert isinstance(msg, Message)
                msgs.append(msg)

    @pytest.mark.parametrize("output_file_eml", ['plain_message.eml'])
    def test_plain_message(self, output_file_eml):
        file_path = os.path.join(self.test_dir, output_file_eml)

        msg = get_plain_text_message()
        msg.replace_header('Subject', '{} - {}'.format(msg['Subject'], output_file_eml))

        with open(file_path, 'wb') as f:
            f.write(msg.as_bytes())

    # ToDo(frennkie) add test that raises deprecated digest error

    @pytest.mark.parametrize("output_file_eml,pub_key,private_key,digest_alg,sig_alg,depr", [
        ("plain_message_signed_by_alice_md5.eml",
         "AliceRSASignByCarl.pem", "AlicePrivRSASign.pem", "md5", "rsa", True),
        ("plain_message_signed_by_alice_sha1.eml",
         "AliceRSASignByCarl.pem", "AlicePrivRSASign.pem", "sha1", "rsa", True),
        ("plain_message_signed_by_alice_sha1_pss.eml",
         "AliceRSASignByCarl.pem", "AlicePrivRSASign.pem", "sha1", "pss", True),
        ("plain_message_signed_by_alice_sha256.eml",
         "AliceRSASignByCarl.pem", "AlicePrivRSASign.pem", "sha256", "rsa", False),
        ("plain_message_signed_by_alice_sha256_pss.eml",
         "AliceRSASignByCarl.pem", "AlicePrivRSASign.pem", "sha256", "pss", False)
    ])
    def test_plain_message_signed_by_alice(self, output_file_eml, pub_key, private_key, digest_alg, sig_alg, depr):
        file_path = os.path.join(self.test_dir, output_file_eml)

        msg = get_plain_text_message()
        msg.replace_header('Subject', '{} - {}'.format(msg['Subject'], output_file_eml))

        with open(os.path.join(FIXTURE_DIR, pub_key), 'rb') as cert_signer_file:
            der_bytes = cert_signer_file.read()
            if pem.detect(der_bytes):
                type_name, headers, der_bytes = pem.unarmor(der_bytes)

            cert_signer = x509.Certificate.load(der_bytes)

        with open(os.path.join(FIXTURE_DIR, private_key), 'rb') as key_signer_file:
            key_bytes = key_signer_file.read()
            if pem.detect(key_bytes):
                _, _, key_bytes = pem.unarmor(key_bytes)

            key_signer = keys.RSAPrivateKey.load(key_bytes)
            key_signer_info = keys.PrivateKeyInfo.load(key_bytes)

        assert isinstance(key_signer_info, keys.PrivateKeyInfo)
        assert isinstance(key_signer, keys.RSAPrivateKey)

        signed_message = sign_message(msg, key_signer_info, cert_signer,
                                      digest_alg=digest_alg, sig_alg=sig_alg,
                                      allow_deprecated=depr)

        assert isinstance(signed_message, email.message.Message)

        with open(file_path, 'wb') as f:
            f.write(signed_message.as_bytes())

    @pytest.mark.parametrize("output_file_eml,pub_key,private_key,incl_self,incl_ca", [
        ("plain_message_signed_by_alice_sha256_incl_false_false.eml",
         "AliceRSASignByCarl.pem", "AlicePrivRSASign.pem", False, False),
        ("plain_message_signed_by_alice_sha256_incl_true_false.eml",
         "AliceRSASignByCarl.pem", "AlicePrivRSASign.pem", True, False),
        ("plain_message_signed_by_alice_sha256_incl_false_true.eml",
         "AliceRSASignByCarl.pem", "AlicePrivRSASign.pem", False, True),
        ("plain_message_signed_by_alice_sha256_incl_true_true.eml",
         "AliceRSASignByCarl.pem", "AlicePrivRSASign.pem", True, True),
    ])
    def test_plain_message_signed_by_alice_includes(self, output_file_eml, pub_key, private_key, incl_self, incl_ca):
        file_path = os.path.join(self.test_dir, output_file_eml)

        msg = get_plain_text_message()
        msg.replace_header('Subject', '{} - {}'.format(msg['Subject'], output_file_eml))

        with open(os.path.join(FIXTURE_DIR, pub_key), 'rb') as cert_signer_file:
            der_bytes = cert_signer_file.read()
            if pem.detect(der_bytes):
                type_name, headers, der_bytes = pem.unarmor(der_bytes)

            cert_signer = x509.Certificate.load(der_bytes)

        with open(os.path.join(FIXTURE_DIR, private_key), 'rb') as key_signer_file:
            key_bytes = key_signer_file.read()
            if pem.detect(key_bytes):
                _, _, key_bytes = pem.unarmor(key_bytes)

            key_signer = keys.RSAPrivateKey.load(key_bytes)
            key_signer_info = keys.PrivateKeyInfo.load(key_bytes)

        assert isinstance(key_signer_info, keys.PrivateKeyInfo)
        assert isinstance(key_signer, keys.RSAPrivateKey)

        if incl_ca:
            with open(os.path.join(FIXTURE_DIR, 'CarlRSA2048Self.pem'), 'rb') as ca_file:
                der_bytes = ca_file.read()
                if pem.detect(der_bytes):
                    type_name, headers, der_bytes = pem.unarmor(der_bytes)

                ca = x509.Certificate.load(der_bytes)

            signed_message = sign_message(msg, key_signer_info, cert_signer,
                                          digest_alg="sha256", sig_alg="rsa",
                                          include_cert_signer=incl_self,
                                          additional_certs=[ca])
        else:
            signed_message = sign_message(msg, key_signer_info, cert_signer,
                                          digest_alg="sha256", sig_alg="rsa",
                                          include_cert_signer=incl_self)

        assert isinstance(signed_message, email.message.Message)

        with open(file_path, 'wb') as f:
            f.write(signed_message.as_bytes())

    @pytest.mark.parametrize("output_file_eml,pub_keys,algorithm", [
        ("plain_message_encrypted_for_bob_aes128_cbc.eml", ["BobRSASignByCarl.pem"], "aes128_cbc"),
        ("plain_message_encrypted_for_bob_aes256_cbc.eml", ["BobRSASignByCarl.pem"], "aes256_cbc"),
        ("plain_message_encrypted_for_bob_tripledes.eml", ["BobRSASignByCarl.pem"], "tripledes_3key"),
        ("plain_message_encrypted_for_alice_and_bob_aes256_cbc.eml",
         ("AliceRSASignByCarl.pem", "BobRSASignByCarl.pem"), "aes256_cbc"),
    ])
    def test_plain_message_encrypted(self, output_file_eml, pub_keys, algorithm):
        file_path = os.path.join(self.test_dir, output_file_eml)

        msg = get_plain_text_message()
        msg.replace_header('Subject', '{} - {}'.format(msg['Subject'], output_file_eml))

        certs = []
        for pub_key in pub_keys:
            certs.append(os.path.join(FIXTURE_DIR, pub_key))

        assert isinstance(get_plain_text_message(), email.message.Message)

        encrypted_message = encrypt_message(msg, certs_recipients=certs)

        with open(file_path, 'wb') as f:
            f.write(encrypted_message.as_bytes())

    @pytest.mark.parametrize("attachments,output_file_eml,pub_keys", [
        (["sample1.pdf"], "msg_w1_att_message_encrypted_for_bob_aes256_cbc.eml",
         ["BobRSASignByCarl.pem"]),
        (["sample2.png", "sample3.txt"], "msg_w2_att_message_encrypted_for_bob_aes256_cbc.eml",
         ["BobRSASignByCarl.pem"])
    ])
    def test_message_with_attachment_encrypted(self, attachments, output_file_eml, pub_keys):
        file_path = os.path.join(self.test_dir, output_file_eml)

        atts = [os.path.join(FIXTURE_DIR, x) for x in attachments]

        msg = get_message(files=atts)
        msg.replace_header('Subject', '{} - {}'.format(msg['Subject'], output_file_eml))

        certs = []
        for pub_key in pub_keys:
            certs.append(os.path.join(FIXTURE_DIR, pub_key))

        assert isinstance(get_plain_text_message(), email.message.Message)

        encrypted_message = encrypt_message(msg, certs_recipients=certs)

        with open(file_path, 'wb') as f:
            f.write(encrypted_message.as_bytes())

    @pytest.mark.parametrize("output_file_eml", ['plain_message_signed_by_alice_encrypted_for_bob.eml'])
    def test_plain_message_signed_by_alice_encrypted_for_bob(self, output_file_eml):
        file_path = os.path.join(self.test_dir, output_file_eml)

        msg = get_plain_text_message()
        msg.replace_header('Subject', '{} - {}'.format(msg['Subject'], output_file_eml))

        key_signer_path = os.path.join(FIXTURE_DIR, 'AlicePrivRSASign.pem')
        cert_signer_path = os.path.join(FIXTURE_DIR, 'AliceRSASignByCarl.pem')

        certs = [os.path.join(FIXTURE_DIR, 'BobRSASignByCarl.pem')]

        signed_encrypted_message = sign_and_encrypt_message(msg, key_signer_path, cert_signer_path, certs)

        with open(file_path, 'wb') as f:
            f.write(signed_encrypted_message.as_bytes())

    #  ToDo(frennkie) test inline images and attachments
    @pytest.mark.parametrize("addr,name,reci,subject", [
        ('alice@example.com', "Alice", "bob@example.com", "Test-Subject"),
        ('alice@example.com', "Alice Anderson", "bob@example.com", "Test-Subject2")
    ])
    def test_make_message(self, addr, name, reci, subject):
        msg = make_msg(sender_addr=addr, sender_name=name,
                       recipients=reci, subject=subject,
                       text="Text Body", html="This is a <strong>HTML</strong> body.",
                       img_list=None, attachments=None)

        assert isinstance(msg, Message)