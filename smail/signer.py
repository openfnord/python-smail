# *-* coding: utf-8 *-*

"""signer.py

Forked from https://github.com/m32/endesive/blob/master/endesive/signer.py

MIT License

Copyright (c) 2018 Grzegorz Makarewicz
Copyright (c) 2020 Robert Habermann

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

"""

import hashlib
from datetime import datetime, timezone

from asn1crypto import cms, algos, core, x509
from asn1crypto.x509 import Certificate as AsnCryptoCertificate
from oscrypto import asymmetric
from oscrypto.asymmetric import dump_certificate


class InvalidSignedMessageError(Exception):
    """
    An exception indicating that the given message is somehow invalid; no signature,
    too many parts, etc.
    """

    pass


class SignerNotFound(Exception):
    """
    An exception indicating that the signer cert was not found in the signed message.
    """


_SIGNATURE_ALGORITHMS = {
    'rsassa_pkcs1v15': asymmetric.rsa_pkcs1v15_verify,
    'rsassa_pss': asymmetric.rsa_pss_verify,
    'dsa': asymmetric.dsa_verify,
    'ecdsa': asymmetric.ecdsa_verify
}


def sign_bytes(data_unsigned: bytes, key_signer: asymmetric.PrivateKey,
               cert_signer: x509.Certificate, digest_alg="sha256",
               sig_alg='rsa', attrs=True, include_cert_signer=True,
               additional_certs=None, signed_value=None, ):
    """Takes bytes, creates a ContentInfo structure and returns it as signed bytes

    Notes:
        cert_signer is mandatory (needed to get Issuer and Serial Number ) but can be
            excluded from signed data.

    Args:
        data_unsigned (bytes): data
        key_signer (:obj:`oscrypto.asymmetric.PrivateKey`): Private key used to sign the
            message.
        cert_signer (:obj:`asn1crypto.x509.Certificate`): Certificate/Public Key
            (belonging to Private Key) that will be included in the signed message.
        digest_alg (str): Digest (Hash) Algorithm - e.g. "sha256"
        sig_alg (str): Signature Algorithm
        attrs (bool): Whether to include signed attributes (signing time). Default
            to True
        include_cert_signer (bool): Whether to include the public certificate of the signer
            in the signed data. Default to True
        additional_certs (:obj:`list` of :obj:`asn1crypto.x509.Certificate`): List of
            additional certificates to be included (e.g. Intermediate or Root CA certs).
        signed_value: unknown


    Returns:
         bytes: signed bytes

    """

    if include_cert_signer:
        certificates = [cert_signer]
    else:
        certificates = []

    if additional_certs:
        for additional in additional_certs:
            if not isinstance(additional, x509.Certificate):
                raise AttributeError("only asn1crypto.x509.Certificate supported")
            certificates.append(additional)

    if digest_alg not in ["md5", "sha1", "sha256", "sha512"]:
        raise AttributeError("digest algorithm unsupported: {}".format(digest_alg))

    if signed_value is None:
        signed_value = getattr(hashlib, digest_alg)(data_unsigned).digest()
    signed_time = datetime.now(tz=timezone.utc)

    signer = {
        'version': 'v1',
        'sid': cms.SignerIdentifier({
            'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                'issuer': cert_signer.issuer,
                'serial_number': cert_signer.serial_number,
            }),
        }),
        'digest_algorithm': algos.DigestAlgorithm({'algorithm': digest_alg}),
        'signature': signed_value,
    }

    pss_digest_alg = digest_alg  # use same digest algorithm for pss signature as for message

    if sig_alg == "rsa":
        signer['signature_algorithm'] = algos.SignedDigestAlgorithm({'algorithm': 'rsassa_pkcs1v15'})

    elif sig_alg == "pss":
        salt_length = getattr(hashlib, pss_digest_alg)().digest_size
        signer['signature_algorithm'] = algos.SignedDigestAlgorithm({
            'algorithm': 'rsassa_pss',
            'parameters': algos.RSASSAPSSParams({
                'hash_algorithm': algos.DigestAlgorithm({'algorithm': pss_digest_alg}),
                'mask_gen_algorithm': algos.MaskGenAlgorithm({
                    'algorithm': algos.MaskGenAlgorithmId('mgf1'),
                    'parameters': {
                        'algorithm': algos.DigestAlgorithmId(pss_digest_alg),
                    }
                }),
                'salt_length': algos.Integer(salt_length),
                'trailer_field': algos.TrailerField(1)
            })
        })

    else:
        raise AttributeError("signature algorithm unsupported: {}".format(sig_alg))

    if attrs:
        if attrs is True:
            signer['signed_attrs'] = [
                cms.CMSAttribute({
                    'type': cms.CMSAttributeType('content_type'),
                    'values': ('data',),
                }),
                cms.CMSAttribute({
                    'type': cms.CMSAttributeType('message_digest'),
                    'values': (signed_value,),
                }),
                cms.CMSAttribute({
                    'type': cms.CMSAttributeType('signing_time'),
                    'values': (cms.Time({'utc_time': core.UTCTime(signed_time)}),)
                }),
            ]
        else:
            signer['signed_attrs'] = attrs

    config = {
        'version': 'v1',
        'digest_algorithms': cms.DigestAlgorithms((
            algos.DigestAlgorithm({'algorithm': digest_alg}),
        )),
        'encap_content_info': {
            'content_type': 'data',
        },
        'certificates': certificates,
        'signer_infos': [
            signer,
        ],
    }
    data_signed = cms.ContentInfo({
        'content_type': cms.ContentType('signed_data'),
        'content': cms.SignedData(config),
    })
    if attrs:
        to_sign = data_signed['content']['signer_infos'][0]['signed_attrs'].dump()
        to_sign = b'\x31' + to_sign[1:]
    else:
        to_sign = data_unsigned

    if sig_alg == "rsa":
        signed_value_signature = asymmetric.rsa_pkcs1v15_sign(key_signer, to_sign, digest_alg.lower())

    elif sig_alg == "pss":
        signed_value_signature = asymmetric.rsa_pss_sign(key_signer, to_sign, pss_digest_alg)

    else:
        raise AttributeError("signature algorithm unsupported: {}".format(sig_alg))

    data_signed['content']['signer_infos'][0]['signature'] = signed_value_signature

    return data_signed.dump()


def verify_bytes(data_unsigned: bytes, content_info: cms.SignedData, cert_signer: asymmetric.Certificate):
    """Takes bytes, content info and signer certificate to verify a signature

    Args:
        data_unsigned (bytes): data
        content_info (:obj:`asn1crypto.cms.SignedData`): The signature data as it is in the email
        cert_signer (:obj:`oscrypto.asymmetric.Certificate`): Certificate/Public Key of the signer


    Returns:
         bytes: the original message, if verification succeeds

    """

    # Convert cert and find issuer and serial
    asn1_cert = AsnCryptoCertificate.load(dump_certificate(cert_signer, encoding='der'))
    issuer = asn1_cert.issuer
    serial_number = asn1_cert.serial_number

    # Find the signer
    signer_info = None
    for signer in content_info['signer_infos']:
        sid = signer['sid'].chosen

        # For some reason the serial_number extracted above is an int, while issuer is an object
        # To compare, we need to use the native serial number from the recipient_info
        if sid['issuer'] == issuer and sid['serial_number'].native == serial_number:
            signer_info = signer
            break

    if signer_info is None:
        raise SignerNotFound()

    digest_hash_algo = signer_info['digest_algorithm']['algorithm'].native

    # Process is different if signer has attrs
    attrs = signer_info['signed_attrs']
    if attrs is not None and not isinstance(attrs, core.Void):
        # Hash message for comparison
        message_digest = getattr(hashlib, digest_hash_algo)(data_unsigned).digest()
        signer_digest = None

        for attr in attrs:
            if attr['type'].native == 'message_digest':
                signer_digest = attr['values'][0].native

        # Check digest
        if signer_digest != message_digest:
            raise InvalidSignedMessageError('Message digest does not match signer digest')

        # Attribute dump is what is signed
        signed_data = attrs.dump()
        signed_data = b'\x31' + signed_data[1:]
    else:
        # Entire message is signed
        signed_data = data_unsigned

    # Find the signature hash algorithm in params
    signature_hash_algo = None
    signer_params = signer_info['signature_algorithm']['parameters']
    if signer_params is not None and not isinstance(signer_params, core.Null) \
            and not isinstance(signer_params, core.Void):
        if 'hash_algorithm' in signer_params:
            signature_hash_algo = signer_params['hash_algorithm']['algorithm'].native

    # If not found, use same algorithm as digest
    if signature_hash_algo is None:
        signature_hash_algo = digest_hash_algo

    # Define the signature check function and verify
    signature_algo = signer_info['signature_algorithm'].signature_algo
    _SIGNATURE_ALGORITHMS[signature_algo](cert_signer, signer_info['signature'].native,
                                          signed_data, signature_hash_algo)

    return data_unsigned
