# coding: utf-8

from asn1crypto import cms, x509
from oscrypto import asymmetric


def get_recipient_info_for_cert(cert, session_key, key_enc_alg="rsaes_pkcs1v15"):
    # cipher = self._get_public_key_cipher()
    # if cipher is None:
    #     return None
    # encrypted_key = cipher.encrypt(session_key)
    # tbs_cert = self._cert["tbs_certificate"]
    # TODO: use subject_key_identifier when available

    assert isinstance(cert, asymmetric.Certificate)

    # ToDo(frennkie) find a better way to copy and build the value for "issue"

    ordered_dict = cert.asn1['tbs_certificate']['issuer'].native
    _issuer = x509.Name.build(name_dict={**ordered_dict}, use_printable=True)

    _serial = cert.asn1['tbs_certificate']['serial_number'].native

    if key_enc_alg in ["rsa", "rsaes_pkcs1v15"]:  # rsa is mapped to rsaes_pkcs1v15 in asn1crypto
        _encrypted_key = asymmetric.rsa_pkcs1v15_encrypt(cert.public_key, session_key)
    else:
        raise NotImplementedError("Unsupported Key Encryption Algorithm")

    return cms.RecipientInfo(
        name="ktri",
        value={
            "version": "v0",
            "rid": cms.RecipientIdentifier(
                name="issuer_and_serial_number",
                value={
                    "issuer": _issuer,
                    "serial_number": _serial,
                },
            ),
            "key_encryption_algorithm": {
                "algorithm": key_enc_alg,
                "parameters": None,
            },
            "encrypted_key": _encrypted_key,
        },
    )
