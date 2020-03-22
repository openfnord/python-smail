# *-* coding: utf-8 *-*

"""signer.py

Forked from https://github.com/m32/endesive/blob/master/endesive/signer.py

MIT License

Copyright (c) 2018 Grzegorz Makarewicz

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

from asn1crypto import cms, algos, core, keys, pem, x509
from oscrypto import asymmetric
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils


def cert2asn(cert, cert_bytes=True):
    if isinstance(cert, x509.Certificate):
        return cert
    if cert_bytes:
        cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    else:
        cert_bytes = cert
    if pem.detect(cert_bytes):
        _, _, cert_bytes = pem.unarmor(cert_bytes)
    return x509.Certificate.load(cert_bytes)


def sign_bytes(data_unsigned, key, cert, other_certs, hashalgo, attrs=True, signed_value=None, pss=False):
    if signed_value is None:
        signed_value = getattr(hashlib, hashalgo)(data_unsigned).digest()
    signed_time = datetime.now(tz=timezone.utc)

    if pss:
        raise NotImplementedError("Not yet fully implemented/tested")

    cert = cert2asn(cert)

    certificates = [cert]
    for i in range(len(other_certs)):
        certificates.append(cert2asn(other_certs[i]))

    signer = {
        'version': 'v1',
        'sid': cms.SignerIdentifier({
            'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                'issuer': cert.issuer,
                'serial_number': cert.serial_number,
            }),
        }),
        'digest_algorithm': algos.DigestAlgorithm({'algorithm': hashalgo}),
        'signature': signed_value,
    }
    if not pss:
        signer['signature_algorithm'] = algos.SignedDigestAlgorithm({'algorithm': 'rsassa_pkcs1v15'})
    else:
        if isinstance(key, keys.PrivateKeyInfo):
            salt_length = key.byte_size - hashes.SHA512.digest_size - 2  # TODO(frennkie) check this
            salt_length = hashes.SHA512.digest_size
        else:
            salt_length = padding.calculate_max_pss_salt_length(key, hashes.SHA512)
        signer['signature_algorithm'] = algos.SignedDigestAlgorithm({
            'algorithm': 'rsassa_pss',
            'parameters': algos.RSASSAPSSParams({
                'hash_algorithm': algos.DigestAlgorithm({'algorithm': 'sha512'}),
                'mask_gen_algorithm': algos.MaskGenAlgorithm({
                    'algorithm': algos.MaskGenAlgorithmId('mgf1'),
                    'parameters': {
                        'algorithm': algos.DigestAlgorithmId('sha512'),
                    }
                }),
                'salt_length': algos.Integer(salt_length),
                'trailer_field': algos.TrailerField(1)
            })
        })

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
            algos.DigestAlgorithm({'algorithm': hashalgo}),
        )),
        'encap_content_info': {
            'content_type': 'data',
        },
        'certificates': certificates,
        # 'crls': [],
        'signer_infos': [
            signer,
        ],
    }
    datas = cms.ContentInfo({
        'content_type': cms.ContentType('signed_data'),
        'content': cms.SignedData(config),
    })
    if attrs:
        tosign = datas['content']['signer_infos'][0]['signed_attrs'].dump()
        tosign = b'\x31' + tosign[1:]
    else:
        tosign = data_unsigned

    if isinstance(key, keys.PrivateKeyInfo):
        key = asymmetric.load_private_key(key)
        if pss:
            signed_value_signature = asymmetric.rsa_pss_sign(
                key,
                tosign,
                'sha512'
            )
        else:
            signed_value_signature = asymmetric.rsa_pkcs1v15_sign(
                key,
                tosign,
                hashalgo.lower()
            )
    else:
        if pss:
            hasher = hashes.Hash(hashes.SHA512(), backend=backends.default_backend())
            hasher.update(tosign)
            digest = hasher.finalize()
            signed_value_signature = key.sign(
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA512()),
                    salt_length=salt_length  # TODO(frennkie) check this
                ),
                utils.Prehashed(hashes.SHA512())
            )
        else:
            signed_value_signature = key.sign(
                tosign,
                padding.PKCS1v15(),
                getattr(hashes, hashalgo.upper())()
            )

    datas['content']['signer_infos'][0]['signature'] = signed_value_signature

    return datas.dump()
