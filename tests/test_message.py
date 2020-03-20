# -*- coding: utf-8 -*-
import email
import os
import smtplib
import unittest
from email.message import Message
from shutil import copyfile

import pytest

from smail import sign_message
from smail import encrypt_message
from smail import sign_and_encrypt_message
from tests.conftest import FIXTURE_DIR
from tests.fixtures import get_plain_text_message


class MailTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
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

    def tearDown(self):
        file_list = [f for f in os.listdir(self.test_dir)]
        # self.assertListEqual(file_list, [
        #     "plain_text_message.eml",
        #     "plain_text_message_signed_by_bob.eml"
        # ])

        # (re-)check that everything is a "Message"
        msgs = []
        for f_name in file_list:
            with open(os.path.join(self.test_dir, f_name), 'rb') as f:
                msg = email.message_from_bytes(f.read())
                self.assertIsInstance(msg, Message)
                msgs.append(msg)

        self.send_messages(msgs)

    def send_messages(self, msgs):
        if not self.smtp_host:
            return

        # ok - SMTP is configured via ENVIRONMENT
        with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
            # if credentials were supplied then login
            if self.smtp_user and self.smtp_pass:
                server.login(self.smtp_user, self.smtp_pass)

            # now loop over messages s
            for msg in msgs:
                for header in msg.items():
                    # make sure that this is not a "example.com" test message
                    if header[0].lower() == "to":
                        self.assertTrue("example.com" not in str(header[1]))

                    if header[0].lower() == "from":
                        self.assertTrue("example.com" not in str(header[1]))

                # finally send the message
                server.send_message(msg)

    @classmethod
    @pytest.fixture(scope='class', autouse=True)
    def plain_text_message(cls):
        cls.plain_text_message = get_plain_text_message()

    # def test_something(self):
    #     # Create a file path
    #     file_path = os.path.join(self.test_dir, 'test1.txt')
    #
    #     # Create a file in the temporary directory
    #     with open(file_path, 'w') as f:
    #         # Write something to it
    #         f.write('The owls are not what they seem1')
    #
    #     # Reopen the file and check if what we read back is the same
    #     with open(file_path) as f:
    #         self.assertEqual(f.read(), 'The owls are not what they seem1')

    # def test_dir_path(self):
    #     # Create a file path
    #     self.assertEqual(self.test_dir, "foobar")

    def test_plain_message(self):
        file_path = os.path.join(self.test_dir, 'plain_message.eml')

        with open(file_path, 'wb') as f:
            f.write(self.plain_text_message.as_bytes())

    def test_plain_message_signed_by_alice(self):
        file_path = os.path.join(self.test_dir, 'plain_message_signed_by_alice.eml')

        with open(os.path.join(FIXTURE_DIR, 'AliceRSASignByCarl.pem'), 'rb') as cert_signer_file:
            cert_signer = cert_signer_file.read()

        with open(os.path.join(FIXTURE_DIR, 'AlicePrivRSASign.pem'), 'rb') as key_signer_file:
            key_signer = key_signer_file.read()

        signed_message = sign_message(self.plain_text_message, cert_signer, key_signer)

        with open(file_path, 'wb') as f:
            f.write(signed_message.as_bytes())

    def test_plain_message_encrypted_for_bob(self):
        file_path = os.path.join(self.test_dir, 'plain_message_encrypted_for_bob.eml')

        with open(os.path.join(FIXTURE_DIR, 'BobRSASignByCarl.pem'), 'rb') as cert_file:
            cert = cert_file.read()

        encrypted_message = encrypt_message(self.plain_text_message, certs_recipients=cert)

        with open(file_path, 'wb') as f:
            f.write(encrypted_message.as_bytes())

    def test_plain_message_signed_by_alice_encrypted_for_bob(self):
        file_path = os.path.join(self.test_dir, 'plain_message_signed_by_alice_encrypted_for_bob.eml')

        with open(os.path.join(FIXTURE_DIR, 'AliceRSASignByCarl.pem'), 'rb') as cert_signer_file:
            cert_signer = cert_signer_file.read()

        with open(os.path.join(FIXTURE_DIR, 'AlicePrivRSASign.pem'), 'rb') as key_signer_file:
            key_signer = key_signer_file.read()

        with open(os.path.join(FIXTURE_DIR, 'BobRSASignByCarl.pem'), 'rb') as cert_file:
            cert = cert_file.read()

        signed_encrypted_message = sign_and_encrypt_message(self.plain_text_message,
                                                            cert_signer, key_signer,
                                                            cert)

        with open(file_path, 'wb') as f:
            f.write(signed_encrypted_message.as_bytes())


if __name__ == "__main__":
    unittest.main()
