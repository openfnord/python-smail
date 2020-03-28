# _*_ coding: utf-8 _*_
import base64
from copy import deepcopy
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart

from smail.signer import sign_bytes


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
                 attrs=True, prefix="", allow_deprecated=False):
    """Takes a message, signs it and returns a new signed message object.

    Args:
        message (:obj:`email.message.Message`): The message object to sign and encrypt.
        key_signer (:obj:`asn1crypto.keys.PrivateKeyInfo`): Private key used to sign the
            message.
        cert_signer (:obj:`asn1crypto.x509.Certificate`): Certificate/Public Key
            (belonging to Private Key) that will be included in the signed message.
        digest_alg (str): Digest (Hash) Algorithm - e.g. "sha256"
        sig_alg (str): Signature Algorithm
        attrs (bool): Whether to include signed attributes (signing time). Default
            to True
        prefix (str): Content type prefix (e.g. "x-"). Default to ""
        allow_deprecated (bool): Whether deprecated digest algorithms should  be allowed.

    Returns:
         :obj:`email.message.Message`: signed message

    """

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

    data_unsigned = copied_msg.as_bytes()
    data_unsigned = data_unsigned.replace(b'\n', b'\r\n')
    data_signed = sign_bytes(data_unsigned, key_signer, cert_signer, digest_alg, sig_alg, attrs=attrs)
    data_signed = base64.encodebytes(data_signed)

    new_msg = MIMEMultipart("signed",
                            protocol="application/{}pkcs7-signature".format(prefix), micalg=micalg)
    # add original headers
    for hrd, values in headers.items():
        for val in values:
            new_msg.add_header(hrd, str(val))
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
