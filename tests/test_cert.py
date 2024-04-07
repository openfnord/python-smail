import os

import pytest
from asn1crypto import cms, core, keys, pem, x509
from oscrypto import asymmetric

from smail.encrypt import get_recipient_info_for_cert

from .conftest import FIXTURE_DIR


class TestCert:
    @pytest.mark.parametrize(
        "file_name,serial,issuer,sig_algo",
        [
            ("AliceRSA2048.pem", 17886239751307353133, "CarlRSA2048", "rsassa_pkcs1v15"),
            ("AliceECp256.pem", 70400699072669113604691775782881115307289436427, "CarlECp256", "ecdsa"),
            ("AlicePSS2048.pem", 643522079216047803454536659318317487253176610229, "CarlPSS2048", "rsassa_pss"),
        ],
    )
    def test_cert_params(self, file_name, serial, issuer, sig_algo):
        with open(os.path.join(FIXTURE_DIR, file_name), "rb") as cert_file:
            der_bytes = cert_file.read()

            if pem.detect(der_bytes):
                type_name, headers, der_bytes = pem.unarmor(der_bytes)

        cert = x509.Certificate.load(der_bytes)

        assert isinstance(cert, x509.Certificate)
        assert cert["tbs_certificate"]["serial_number"].native == serial
        assert cert["tbs_certificate"]["issuer"].human_friendly == f"Common Name: {issuer}"
        assert cert["tbs_certificate"]["issuer"].native["common_name"] == issuer
        assert cert["signature_algorithm"].signature_algo == sig_algo

    @pytest.mark.parametrize(
        "file_name,serial,issuer,sig_algo",
        [
            ("AliceRSA2048.pem", 17886239751307353133, "CarlRSA2048", "rsa"),
            ("AliceECp256.pem", 70400699072669113604691775782881115307289436427, "CarlECp256", "ec"),
            # TODO(frennkie) does not work on Windows.. check Linux; maybe open issue with oscrypto
            # ("AlicePSS2048.pem", 643522079216047803454536659318317487253176610229, "CarlPSS2048", "rsa")
        ],
    )
    def test_oscrypto_load_certificate(self, file_name, serial, issuer, sig_algo):
        cert = asymmetric.load_certificate(os.path.join(FIXTURE_DIR, file_name))

        assert isinstance(cert, asymmetric.Certificate)
        assert isinstance(cert.asn1, x509.Certificate)
        assert isinstance(cert.public_key, asymmetric.PublicKey)
        assert isinstance(cert.public_key.asn1, keys.PublicKeyInfo)
        assert cert.asn1["tbs_certificate"]["serial_number"].native == serial
        assert cert.asn1["tbs_certificate"]["issuer"].human_friendly == f"Common Name: {issuer}"
        assert cert.asn1["tbs_certificate"]["issuer"].native["common_name"] == issuer
        assert cert.public_key.algorithm == sig_algo
        assert cert.public_key.asn1.algorithm == sig_algo
        assert isinstance(cert.asn1["signature_algorithm"]["parameters"], (core.Null, core.Void))
        assert not cert.asn1["signature_algorithm"]["parameters"].native

    @pytest.mark.parametrize(
        "file_name,serial,issuer,sig_algo",
        [
            ("AliceRSA2048.pem", 84724501279626539432081479560025710686849292165, "CarlRSA2048", "rsa"),
            ("AliceECp256.pem", 70400699072669113604691775782881115307289436427, "CarlECp256", "ec"),
            # TODO(frennkie) does not work on Windows.. check Linux; maybe open issue with oscrypto
            # ("AlicePSS2048.pem", 643522079216047803454536659318317487253176610229, "CarlPSS2048", "rsassa_pss")
        ],
    )
    def test_oscrypto_load_public_key(self, file_name, serial, issuer, sig_algo):
        public_key = asymmetric.load_public_key(os.path.join(FIXTURE_DIR, file_name))

        assert isinstance(public_key, asymmetric.PublicKey)
        assert isinstance(public_key.asn1, keys.PublicKeyInfo)
        assert public_key.algorithm == sig_algo
        assert public_key.asn1.algorithm == sig_algo

    @pytest.mark.parametrize(
        "file_name,sig_algo,bit_size",
        [
            ("AlicePrivRSA2048.pem", "rsa", 2048),
            ("AlicePrivECp256.pem", "ec", 256),
            # TODO(frennkie) does not work on Windows.. check Linux; maybe open issue with oscrypto
            # ("AlicePrivPSS2048.pem",  "rsassa_pss")
        ],
    )
    def test_oscrypto_load_private_key(self, file_name, sig_algo, bit_size):
        private_key = asymmetric.load_private_key(os.path.join(FIXTURE_DIR, file_name))

        assert isinstance(private_key, asymmetric.PrivateKey)
        assert isinstance(private_key.asn1, keys.PrivateKeyInfo)
        assert isinstance(private_key.public_key, asymmetric.PublicKey)
        assert isinstance(private_key.public_key.asn1, keys.PublicKeyInfo)
        assert private_key.bit_size == bit_size
        assert private_key.algorithm == sig_algo

    @pytest.mark.parametrize(
        "file_name,key,value",
        [
            ("AliceRSA2048.pem", "common_name", "CarlRSA2048"),
            # verisign has a list in the issuer OrderedDict..?!
            # ("verisign_intermediate.pem", "common_name", "VeriSign Class 3 Public Primary Certification Authority - G5"),
            ("domain_in_o_component.pem", "common_name", "Go Daddy Secure Certification Authority"),
            # ToDo(frennkie) ec currently not supported
            # ("AliceECp256.pem", 70400699072669113604691775782881115307289436427, "CarlECp256", "ec")
            # ToDo(frennkie) does not work on Windows.. check Linux; maybe open issue with oscrypto
            # ("AlicePSS2048.pem", 643522079216047803454536659318317487253176610229, "CarlPSS2048", "rsassa_pss")
        ],
    )
    def test_oscrypto_recipient_info(self, file_name, key, value):
        cert = asymmetric.load_certificate(os.path.join(FIXTURE_DIR, file_name))

        assert isinstance(cert, asymmetric.Certificate)

        session_key = os.urandom(16)
        ri = get_recipient_info_for_cert(cert, session_key)

        assert isinstance(ri, cms.KeyTransRecipientInfo)
        assert isinstance(ri["rid"].chosen, cms.IssuerAndSerialNumber)
        assert isinstance(ri["rid"].chosen["issuer"].contents, bytes)

        assert cert.asn1["tbs_certificate"]["issuer"].native[key] == value
        # assert cert.asn1['tbs_certificate']['issuer'].native == b"foo"
        assert isinstance(cert.asn1["tbs_certificate"]["issuer"].contents, bytes)

        # assert cert.asn1['tbs_certificate']['issuer'].contents == ri.chosen['rid'].chosen['issuer'].contents
