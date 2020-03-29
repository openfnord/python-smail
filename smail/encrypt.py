# _*_ coding: utf-8 _*_

from base64 import b64encode
from copy import deepcopy
from email import message_from_string, message_from_bytes
from email.mime.text import MIMEText

from asn1crypto import cms, x509
from oscrypto import asymmetric

from .ciphers import TripleDes, AesCbc
from .utils import wrap_lines


class UnsupportedAlgorithmError(Exception):
    """
    An exception indicating that an unsupported cipher algorithm was specified
    """

    pass


def _get_content_encryption_algorithm(alg):
    algs = {
        "tripledes_3key": TripleDes(alg, key_size=24),
        "aes128_cbc": AesCbc(alg, key_size=16),
        "aes256_cbc": AesCbc(alg, key_size=32)
    }
    try:
        return algs[alg]
    except KeyError:
        raise UnsupportedAlgorithmError("selected algorithm \"{}\" not in: "
                                        "{}".format(alg, ", ".join(algs.keys())))


def _get_key_encryption_algorithm(alg):
    algs = {
        "rsaes_pkcs1v15": asymmetric.rsa_pkcs1v15_encrypt,
        "rsa": asymmetric.rsa_pkcs1v15_encrypt  # rsa is mapped to rsaes_pkcs1v15 in asn1crypto
    }
    try:
        return algs[alg]
    except KeyError:
        raise UnsupportedAlgorithmError("selected algorithm \"{}\" not in: "
                                        "{}".format(alg, ", ".join(algs.keys())))


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

    # ToDo(frennkie) find a better way to copy and build the value for "issue"

    ordered_dict = cert.asn1['tbs_certificate']['issuer'].native
    issuer = x509.Name.build(name_dict={**ordered_dict}, use_printable=True)

    serial = cert.asn1['tbs_certificate']['serial_number'].native

    key_enc_func = _get_key_encryption_algorithm(key_enc_alg)
    encrypted_key = key_enc_func(cert.public_key, session_key)

    return cms.RecipientInfo(
        name="ktri",
        value={
            "version": "v0",
            "rid": cms.RecipientIdentifier(
                name="issuer_and_serial_number",
                value={
                    "issuer": issuer,
                    "serial_number": serial,
                },
            ),
            "key_encryption_algorithm": {
                "algorithm": key_enc_alg,
                "parameters": None,
            },
            "encrypted_key": encrypted_key,
        },
    )


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

    # Check/Get the chosen algorithms for content and key encryption
    block_cipher = _get_content_encryption_algorithm(content_enc_alg)
    _ = _get_key_encryption_algorithm(key_enc_alg)

    # Get the message content. This could be a string, bytes or a message object
    passed_as_str = isinstance(message, str)

    if passed_as_str:
        message = message_from_string(message)

    passed_as_bytes = isinstance(message, bytes)
    if passed_as_bytes:
        message = message_from_bytes(message)

    # Extract the message payload without conversion, & the outermost MIME header / Content headers. This allows
    # the MIME content to be rendered for any outermost MIME type incl. multipart
    copied_msg = deepcopy(message)

    headers = {}
    # besides some special ones (e.g. Content-Type) remove all headers before encrypting the body content
    for hdr_name in copied_msg.keys():
        if hdr_name in ["Content-Type", "MIME-Version", "Content-Transfer-Encoding"]:
            continue

        values = copied_msg.get_all(hdr_name)
        if values:
            del copied_msg[hdr_name]
            headers[hdr_name] = values

    content = copied_msg.as_string()
    recipient_infos = []

    for recipient_info in _iterate_recipient_infos(certificates, block_cipher.session_key, key_enc_alg=key_enc_alg):
        if recipient_info is None:
            raise ValueError("Unknown public-key algorithm")
        recipient_infos.append(recipient_info)

    # Encode the content
    encrypted_content_info = block_cipher.encrypt(content)

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
    encoded_content = "\n".join(wrap_lines(b64encode(enveloped_data.dump()), 64))

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
    for hrd, values in headers.items():
        for val in values:
            result_msg.add_header(hrd, str(val))

    # return the same type as was passed in
    if passed_as_bytes:
        return result_msg.as_bytes()
    elif passed_as_str:
        return result_msg.as_string()
    else:
        return result_msg
