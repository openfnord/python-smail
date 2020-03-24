# _*_ coding: utf-8 _*_
import os

from asn1crypto import x509, pem
from cryptography.hazmat.backends.openssl.rsa import RSAPrivateKeyWithSerialization

from smail.cert import Certificate, key_and_certs_from_pkcs12
from .conftest import FIXTURE_DIR


class TestCert:

    # @classmethod
    # def setup_class(cls):
    #     """ setup any state specific to the execution of the given class (which
    #     usually contains tests).
    #     """
    #
    #     cls.openssl_binary = os.environ.get("OPENSSL_BINARY", None)
    #     if not cls.openssl_binary:
    #         cls.openssl_binary = "openssl"
    #
    # @classmethod
    # def teardown_class(cls):
    #     """ teardown any state that was previously setup with a call to
    #     setup_class.
    #     """
    #     pass

    def test_cert_from_pem_file(self):
        cert = Certificate.from_pem_file(os.path.join(FIXTURE_DIR, 'CarlRSASelf.pem'))
        assert isinstance(cert, Certificate)
        assert cert.self_signed

    def test_cert_from_pem(self):
        with open(os.path.join(FIXTURE_DIR, 'CarlRSASelf.pem'), 'rb') as f:
            cert = Certificate.from_pem(f.read())
            assert isinstance(cert, Certificate)

    # def test_cert_from_pem_str_raises_exception(self):
    #     with open(os.path.join(FIXTURE_DIR, 'CarlRSASelf.pem')) as f:
    #         with self.assertRaises(TypeError):
    #             Certificate.from_pem(f.read())

    def test_cert_from_der_file(self):
        cert = Certificate.from_der_file(os.path.join(FIXTURE_DIR, 'google_cert.der'))
        assert isinstance(cert, Certificate)

    def test_cert_from_der(self):
        with open(os.path.join(FIXTURE_DIR, 'google_cert.der'), 'rb') as f:
            cert = Certificate.from_der(f.read())
            assert isinstance(cert, Certificate)

    def test_key_and_certs_from_pkcs12(self):
        with open(os.path.join(FIXTURE_DIR, 'BobRSASignByCarl_password.p12'), 'rb') as f:
            key, cert, certs = key_and_certs_from_pkcs12(f.read(),
                                                         password="password")

        assert isinstance(key, RSAPrivateKeyWithSerialization)
        assert isinstance(cert, Certificate)
        assert len(certs) == 1
        assert isinstance(certs[0], Certificate)

    def test_recipient_info(self):
        with open(os.path.join(FIXTURE_DIR, 'AliceRSASignByCarl.pem'), 'rb') as cert_signer_file:
            der_bytes = cert_signer_file.read()

            if pem.detect(der_bytes):
                type_name, headers, der_bytes = pem.unarmor(der_bytes)

            asn1crypto_cert = x509.Certificate.load(der_bytes)

        with open(os.path.join(FIXTURE_DIR, 'AliceRSASignByCarl.pem'), 'rb') as cert_file:
            bytes_cert = cert_file.read()

        smail_cert = Certificate.from_pem_file(os.path.join(FIXTURE_DIR, 'AliceRSASignByCarl.pem'))

        assert isinstance(bytes_cert, bytes)
        assert isinstance(asn1crypto_cert, x509.Certificate)
        assert isinstance(smail_cert, Certificate)
        assert smail_cert.self_signed == asn1crypto_cert.self_issued

        # session_key = os.urandom(16)
        # cipher = get_cipher("aes256_cbc")
        # # encrypted_key = cipher.encrypt(session_key)
        #
        # ri1 = load_recipient_info(asn1crypto_cert, session_key)
        # assert isinstance(ri1, RecipientInfo)
        #
        # ri2 = iterate_recipient_infos(bytes_cert, session_key)
        # for ri2_item in ri2:
        #     assert isinstance(ri2_item, RecipientInfo)
        #
        #     assert ri1.parse() == ri2_item.parse()
