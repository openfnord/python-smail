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


def sign_message(msg, key, cert, other_certs=None, digest_alg='sha256', sig_alg='rsa',
                 attrs=True, prefix="", allow_deprecated=False):
    if other_certs is None:
        other_certs = []

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
    copied_msg = deepcopy(msg)

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
    data_signed = sign_bytes(data_unsigned, key, cert, other_certs, digest_alg, sig_alg, attrs=attrs, signed_value=None)
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
