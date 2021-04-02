# _*_ coding: utf-8 _*_
import base64
from copy import deepcopy
from email import message_from_bytes
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart

from asn1crypto import x509, cms
from oscrypto import asymmetric

from smail.signer import sign_bytes, verify_bytes, InvalidSignedMessageError


class UnsupportedDigestError(Exception):
    """
    An exception indicating that an unsupported digest algorithm was specified
    """

    pass


class DeprecatedDigestError(Exception):
    """
    An exception indicating that a deprecated digest algorithm was specified
    """

    pass


class UnsupportedSignatureError(Exception):
    """
    An exception indicating that an unsupported signature algorithm was specified
    """

    pass


def sign_message(message, key_signer, cert_signer,
                 digest_alg='sha256', sig_alg='rsa',
                 attrs=True, prefix="", allow_deprecated=False,
                 include_cert_signer=True,
                 additional_certs=None,
                 multipart_class=MIMEMultipart):
    """Takes a message, signs it and returns a new signed message object.

    Args:
        message (:obj:`email.message.Message`): The message object to sign.
        key_signer (`bytes`, `str` or :obj:`asn1crypto.keys.PrivateKeyInfo` or
            :obj:`oscrypto.asymmetric.PrivateKey`): Private key used to sign the message. (A byte
            string of file contents, a unicode string filename or an asn1crypto.keys.PrivateKeyInfo
            object)
        cert_signer (`bytes`, `str` or :obj:`asn1crypto.x509.Certificate` or
            :obj:`oscrypto.asymmetric.Certificate`): Certificate/Public Key (belonging to Private
            Key) that will be included in the signed message. (A byte string of file contents, a
            unicode string filename or an asn1crypto.x509.Certificate object)
        digest_alg (str): Digest (Hash) Algorithm - e.g. "sha256"
        sig_alg (str): Signature Algorithm
        attrs (bool): Whether to include signed attributes (signing time). Default
            to True
        prefix (str): Content type prefix (e.g. "x-"). Default to ""
        allow_deprecated (bool): Whether deprecated digest algorithms should be allowed.
        include_cert_signer (bool): Whether to include the public certificate of the signer
            in the signed data. Default to True
        additional_certs (:obj:`list` of :obj:`asn1crypto.x509.Certificate`): List of
            additional certificates to be included (e.g. Intermediate or Root CA certs).
        multipart_class (class): Which MIMEMultiPart class should be used.

    Returns:
         :obj:`email.message.Message`: signed message

    """

    # private key
    if not isinstance(key_signer, asymmetric.PrivateKey):
        key_signer = asymmetric.load_private_key(key_signer)

    # cert
    if not isinstance(cert_signer, x509.Certificate):
        cert_signer_oscrypto = asymmetric.load_certificate(cert_signer)
        cert_signer = cert_signer_oscrypto.asn1

    if digest_alg == "md5":
        micalg = "md5"
        if allow_deprecated is False:
            raise DeprecatedDigestError("{} is deprecated".format(digest_alg))
    elif digest_alg == "sha1":
        micalg = "sha-1"
        if allow_deprecated is False:
            raise DeprecatedDigestError("{} is deprecated".format(digest_alg))
    elif digest_alg == "sha256":
        micalg = "sha-256"
    elif digest_alg == "sha512":
        micalg = "sha-512"
    else:
        raise UnsupportedDigestError("{} is unknown or unsupported".format(digest_alg))

    if sig_alg == "rsa":
        pass
    elif sig_alg == "pss":
        pass
    else:
        raise UnsupportedSignatureError("{} is unknown or unsupported".format(sig_alg))

    additional_x509 = []
    if additional_certs:
        for additional in additional_certs:
            if not isinstance(additional, x509.Certificate):
                additional_oscrypto = asymmetric.load_certificate(additional)
                additional = additional_oscrypto.asn1

            additional_x509.append(additional)

    # make a deep copy of original message to avoid any side effects (original will not be touched)
    copied_msg = deepcopy(message)

    headers = {}
    # besides some special ones (e.g. Content-Type) remove all headers before signing the body content
    for hdr_name in copied_msg.keys():
        if hdr_name in ["Content-Type", "MIME-Version", "Content-Transfer-Encoding"]:
            continue

        values = copied_msg.get_all(hdr_name)
        if values:
            del copied_msg[hdr_name]
            headers[hdr_name] = values

    data_unsigned = copied_msg.as_string().encode()
    data_unsigned = data_unsigned.replace(b'\n', b'\r\n')
    data_signed = sign_bytes(data_unsigned, key_signer, cert_signer, digest_alg, sig_alg, attrs=attrs,
                             include_cert_signer=include_cert_signer, additional_certs=additional_x509)
    data_signed = base64.encodebytes(data_signed)

    new_msg = multipart_class("signed",
                              protocol="application/{}pkcs7-signature".format(prefix), micalg=micalg)
    # add original headers
    for hdr, values in headers.items():
        for val in values:
            new_msg.add_header(hdr, str(val))
    new_msg.preamble = "This is an S/MIME signed message"

    # attach original message
    new_msg.attach(copied_msg)

    msg_signature = MIMEBase('application', '{}pkcs7-signature'.format(prefix), name="smime.p7s")
    msg_signature.add_header('Content-Transfer-Encoding', 'base64')
    msg_signature.add_header('Content-Disposition', 'attachment', filename="smime.p7s")
    msg_signature.add_header('Content-Description', 'S/MIME Cryptographic Signature')
    msg_signature.__delitem__("MIME-Version")
    msg_signature.set_payload(data_signed)

    new_msg.attach(msg_signature)

    return new_msg


def verify_message(message, cert_signer, prefix=""):
    """Takes a signed message and verifies the signature. Returns the original unsigned message.

    Args:
        message (:obj:`email.message.Message`): The message object to sign.
        cert_signer (`bytes`, `str` or :obj:`asn1crypto.x509.Certificate` or
            :obj:`oscrypto.asymmetric.Certificate`): Certificate/Public Key of the signer
        prefix (str): Content type prefix (e.g. "x-"). Default to ""

    Returns:
         :obj:`email.message.Message`: original message

    """
    # Find the signature
    signature_data = None
    original_message = None
    for part in message.walk():
        if part.get_content_type() == 'multipart/signed':
            # This part should consist of 2 messages; the original and the signature
            parts = part.get_payload()
            part_count = len(parts)
            if part_count != 2:
                raise InvalidSignedMessageError('Too many parts: {} expected 2'.format(part_count))

            for sub_part in parts:
                if sub_part.get_content_type() == 'application/{}pkcs7-signature'.format(prefix):
                    signature_data = cms.ContentInfo.load(sub_part.get_payload(decode=True))
                else:
                    original_message = sub_part.as_bytes().replace(b'\n', b'\r\n')

    if signature_data is None:
        raise InvalidSignedMessageError('No signature found in message')

    signature_type = signature_data['content_type'].native
    if signature_type != 'signed_data':
        raise InvalidSignedMessageError('Signature type is "{}" instead of "signed_data"'.format(signature_type))

    signature_data = signature_data['content']

    # Load the signer certificate and get issuer and serial for comparison
    signer_cert = asymmetric.load_certificate(cert_signer)
    data = verify_bytes(original_message, signature_data, signer_cert)

    # The message is verified, attach encapsulated headers
    verified_message = message_from_bytes(data)

    # Add back headers from the original message, but skip some that are set by encryption
    for hdr_name in message.keys():
        if hdr_name.lower() in ["content-type", "content-transfer-encoding",
                                "content-disposition", "content-description"]:
            continue

        for val in message.get_all(hdr_name):
            verified_message.add_header(hdr_name, str(val))

    return verified_message
