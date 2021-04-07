# _*_ coding: utf-8 _*_
import base64
from email.mime.text import MIMEText

from asn1crypto import cms
from asn1crypto.x509 import Certificate as AsnCryptoCertificate
from asn1crypto.algos import Rc2Params
from oscrypto import asymmetric
from oscrypto.asymmetric import dump_certificate

from .ciphers import encrypt_content, decrypt_content, encrypt_key, decrypt_key
from .message import encode_message, decode_message


class InvalidMessageFormat(Exception):
    """
    An exception indicating that the passed message is not a valid encrypted message
    """

    pass


class RecipientNotFound(Exception):
    """
    An exception indicating that the recipient indicated in the cert/key was not found
    in the encrypted email as an intended recipient
    """

    pass


def _iterate_recipient_infos(certs, session_key, key_enc_alg):
    """Yields the recipient identifier data needed for an encrypted message.

    Args:
        certs (:obj:`list` of :obj:`oscrypto.asymmetric.Certificate`): Certificate object
        session_key (bytes): Session key
        key_enc_alg (str): Key Encryption Algorithm

    Yields:
        :obj:`asn1crypto.cms.RecipientInfo`

    """

    for cert in certs:
        yield get_recipient_info_for_cert(cert, session_key, key_enc_alg)


def get_recipient_info_for_cert(cert, session_key, key_enc_alg="rsaes_pkcs1v15"):
    """Returns the recipient identifier data needed for an encrypted message.

    Args:
        cert (:obj:`oscrypto.asymmetric.Certificate`): Certificate object
        session_key (bytes): Session key
        key_enc_alg (str): Key Encryption Algorithm

    Returns:
        :obj:`asn1crypto.cms.RecipientInfo`

    """
    assert isinstance(cert, asymmetric.Certificate)

    # TODO: use subject_key_identifier when available

    # load asymmetric.Certificate as asn1crypto.x509.Certificate in order
    # to get issuer and serial in correct format for CMS Recipient Info object
    asn1_cert = AsnCryptoCertificate.load(dump_certificate(cert, encoding='der'))

    # asymmetrically encrypt session key for recipient (identified by issuer + serial)
    encrypted_key = encrypt_key(key_enc_alg, cert.public_key, session_key)

    return cms.KeyTransRecipientInfo({
        "version": "v0",
        "rid": cms.IssuerAndSerialNumber({
            "issuer": asn1_cert.issuer,
            "serial_number": asn1_cert.serial_number,
        }),
        "key_encryption_algorithm": {
            "algorithm": key_enc_alg,
            "parameters": None,
        },
        "encrypted_key": encrypted_key,
    })


def encrypt_message(message, certs_recipients,
                    content_enc_alg="aes256_cbc", key_enc_alg="rsaes_pkcs1v15", prefix=""):
    """Takes a message and returns a new message with the original content as encrypted body

    Take the contents of the message parameter, formatted as in RFC 2822 (type bytes, str or
        message) and encrypts them, so that they can only be read by the intended recipient
        specified by pubkey.

    Args:
        message (bytes, str or :obj:`email.message.Message`): Message to be encrypted.
        certs_recipients (:obj:`list` of `bytes`, `str` or :obj:`asn1crypto.x509.Certificate` or
            :obj:`oscrypto.asymmetric.Certificate): A list of byte string of file contents, a
            unicode string filename or an asn1crypto.x509.Certificate object
        key_enc_alg (str): Key Encryption Algorithm
        content_enc_alg (str): Content Encryption Algorithm
        prefix (str): Content type prefix (e.g. "x-"). Default to ""

    Returns:
        :obj:`message`: The new encrypted message (type str or message, as per input).

    Todo:
        TODO(frennkie) cert_recipients..?!

    """

    certificates = []
    for cert in certs_recipients:
        if isinstance(cert, asymmetric.Certificate):
            certificates.append(cert)
        else:
            certificates.append(asymmetric.load_certificate(cert))

    # Convert any input to message object
    copied_msg, orig_type = decode_message(message)

    headers = {}
    # besides some special ones (e.g. Content-Type) remove all headers before encrypting the body content
    for hdr_name in copied_msg.keys():
        if hdr_name.lower() in ["content-type", "mime-version", "content-transfer-encoding"]:
            continue

        values = copied_msg.get_all(hdr_name)
        if values:
            del copied_msg[hdr_name]
            headers[hdr_name] = values

    content = copied_msg.as_string()
    recipient_infos = []

    # Encode the content
    session_key, iv, ciphertext = encrypt_content(content_enc_alg, content)

    # Wrap content in EncryptedContentInfo
    encrypted_content_info = {
        "content_type": "data",
        "content_encryption_algorithm": {
            "algorithm": content_enc_alg,
            "parameters": iv,
        },
        "encrypted_content": ciphertext,
    }

    for recipient_info in _iterate_recipient_infos(certificates, session_key, key_enc_alg=key_enc_alg):
        if recipient_info is None:
            raise ValueError("Unknown public-key algorithm")
        recipient_infos.append(recipient_info)

    # Build the enveloped data and encode in base64
    enveloped_data = cms.ContentInfo(
        {
            "content_type": "enveloped_data",
            "content": {
                "version": "v0",
                "recipient_infos": recipient_infos,
                "encrypted_content_info": encrypted_content_info,
            },
        }
    )
    encoded_content = base64.encodebytes(enveloped_data.dump()).decode()

    # Create the resulting message
    result_msg = MIMEText(encoded_content)
    overrides = (
        ("MIME-Version", "1.0"),
        (
            "Content-Type",
            "application/{}pkcs7-mime; smime-type=enveloped-data; name=smime.p7m".format(prefix),
        ),
        ("Content-Transfer-Encoding", "base64"),
        ("Content-Disposition", "attachment; filename=smime.p7m"),
    )

    for name, value in list(copied_msg.items()):
        if name in [x for x, _ in overrides]:
            continue
        result_msg.add_header(name, str(value))

    for name, value in overrides:
        if name in result_msg:
            del result_msg[name]
        result_msg[name] = value

    # add original headers
    for hdr, values in headers.items():
        for val in values:
            result_msg.add_header(hdr, str(val))

    # return the same type as was passed in
    return encode_message(result_msg, orig_type)


def decrypt_message(message, cert_recipient, key_recipient, key_password=None, prefix=""):
    """Takes an encrypted message and returns a new message with the decrypted content as its body

    Take the contents of the message parameter, formatted as in RFC 2822 (type bytes, str or
        message) and decrypts them, using the private key in key_recipient.

    Args:
        message (`bytes`, `str` or :obj:`email.message.Message`): Message to be decrypted.
        cert_recipient (:obj:`list` of `bytes`, `str` or :obj:`asn1crypto.x509.Certificate`):
            A byte string of file contents, a unicode string filename or an
            asn1crypto.x509.Certificate object
        key_recipient (:obj:`list` of `bytes`, `str` or :obj:`asn1crypto.keys.PrivateKeyInfo`):
            A byte string of file contents, a unicode string filename or an
            asn1crypto.keys.PrivateKeyInfo object
        key_password: (`str`): The password for the private key (optional)
        prefix (`str`): Content type prefix (e.g. "x-"). Default to ""

    Returns:
        :obj:`message`: The new decrypted message (type str or message, as per input).
    """

    # Convert any input to message object
    copied_msg, orig_type = decode_message(message)

    encrypted_content = None
    for part in copied_msg.walk():
        if part.get_content_type() == 'application/{}pkcs7-mime'.format(prefix):
            encrypted_content = part.get_payload(decode=True)
            break

    if encrypted_content is None:
        raise InvalidMessageFormat()

    # Load certificate and PK
    recipient_cert = asymmetric.load_certificate(cert_recipient)
    recipient_key = asymmetric.load_private_key(key_recipient, key_password)

    # Convert to ASN cert and extract identifying info
    asn1_cert = AsnCryptoCertificate.load(dump_certificate(recipient_cert, encoding='der'))
    issuer = asn1_cert.issuer
    serial_number = asn1_cert.serial_number

    # Find the recipient in the infos by looking for the same rid as in the certificate
    encrypted_key = None
    key_encryption_alg = None
    content_info = cms.ContentInfo.load(encrypted_content)
    for recipient_info in content_info['content']['recipient_infos']:
        key_trans_recipient_info = recipient_info.chosen
        rid = key_trans_recipient_info['rid'].chosen

        # For some reason the serial_number extracted above is an int, while issuer is an object
        # To compare, we need to use the native serial number from the recipient_info
        if rid['issuer'] == issuer and rid['serial_number'].native == serial_number:
            key_encryption_alg = key_trans_recipient_info['key_encryption_algorithm']['algorithm'].native
            encrypted_key = key_trans_recipient_info['encrypted_key'].native
            break

    if encrypted_key is None:
        # This email cannot be decrypted by this key
        raise RecipientNotFound()

    # Decrypt key
    session_key = decrypt_key(key_encryption_alg, recipient_key, encrypted_key)

    # Get decryption algorithm and params
    encrypted_content_info = content_info['content']['encrypted_content_info']
    algorithm_info = encrypted_content_info['content_encryption_algorithm']
    content_encryption_alg = algorithm_info['algorithm'].native

    # Workaround for a bug in asn1crypto - https://github.com/wbond/asn1crypto/issues/204
    if isinstance(algorithm_info['parameters'], Rc2Params):
        iv = algorithm_info['parameters']['iv'].native
    else:
        iv = algorithm_info.encryption_iv

    # Decrypt content
    ciphertext = encrypted_content_info['encrypted_content'].native
    decrypted_content = decrypt_content(content_encryption_alg, session_key, iv, ciphertext)
    decrypted_message, _ = decode_message(decrypted_content)

    # Add back headers from the original message, but skip some that are set by encryption
    for hdr_name in copied_msg.keys():
        if hdr_name.lower() in ["content-type", "mime-version", "content-transfer-encoding"]:
            continue

        for val in copied_msg.get_all(hdr_name):
            decrypted_message.add_header(hdr_name, str(val))

    # return the same type as was passed in
    return encode_message(decrypted_message, orig_type)
