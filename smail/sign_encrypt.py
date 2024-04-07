from copy import deepcopy
from email import message_from_bytes, message_from_string

from asn1crypto import x509
from oscrypto import asymmetric

from .encrypt import encrypt_message
from .sign import sign_message


def sign_and_encrypt_message(
        message,
        key_signer,
        cert_signer,
        certs_recipients,
        digest_alg="sha256",
        sig_alg="rsa",
        attrs=True,
        prefix="",
        content_enc_alg="aes256_cbc",
        key_enc_alg="rsaes_pkcs1v15",
):
    """Takes a message, signs and encrypts it and returns a new signed and encrypted message object.

    Args:
        message (:obj:`email.message.Message`): The message object to sign and encrypt.

        key_signer (`bytes`, `str` or :obj:`asn1crypto.keys.PrivateKeyInfo`): Private key used to
            sign the message. (A byte string of file contents, a unicode string filename or an
            asn1crypto.keys.PrivateKeyInfo object)
        cert_signer (`bytes`, `str` or :obj:`asn1crypto.x509.Certificate`): Certificate/Public Key
            (belonging to Private Key) that will be included in the signed message. (A byte string of file
            contents, a unicode string filename or an asn1crypto.x509.Certificate object)
        certs_recipients (:obj:`list` of `bytes`, `str` or :obj:`asn1crypto.x509.Certificate`): A
            list of byte string of file contents, a unicode string filename or an
            asn1crypto.x509.Certificate object for which the message should be encrypted.
        digest_alg (str): Digest (Hash) Algorithm - e.g. "sha256"
        sig_alg (str): Signature Algorithm
        attrs (bool): Whether to include signed attributes (signing time). Default
            to True
        prefix (str): Content type prefix (e.g. "x-"). Default to ""
        content_enc_alg (str): Content Encryption Algorithm - e.g. aes256_cbc
        key_enc_alg: Key Encryption Algorithm

    Returns:
         :obj:`email.message.Message`: signed and encrypted message

    Todo:
        payload not used anymore.. does this still work for MultiPart?!

    """

    # TODO(frennkie) rewrite this!
    # Get the message content. This could be a string, bytes or a message object
    passed_as_str = isinstance(message, str)
    if passed_as_str:
        message = message_from_string(message)

    passed_as_bytes = isinstance(message, bytes)
    if passed_as_bytes:
        message = message_from_bytes(message)

    # private key
    key_signer = asymmetric.load_private_key(key_signer)
    if not isinstance(key_signer, asymmetric.PrivateKey):
        raise AttributeError("only oscrypto.asymmetric.PrivateKey supported here now")

    # cert
    cert_signer_oscrypto = asymmetric.load_certificate(cert_signer)
    cert_signer = cert_signer_oscrypto.asn1
    if not isinstance(cert_signer, x509.Certificate):
        raise AttributeError("only asn1crypto.x509.Certificate supported here now")

    certs_recipients = [asymmetric.load_certificate(x) for x in certs_recipients]

    # Extract the message payload without conversion, & the outermost MIME header / Content headers. This allows
    # the MIME content to be rendered for any outermost MIME type incl. multipart
    copied_msg = deepcopy(message)

    message_signed = sign_message(
        copied_msg, key_signer, cert_signer, digest_alg=digest_alg, sig_alg=sig_alg, attrs=attrs, prefix=prefix
    )

    message_signed_enveloped = encrypt_message(
        message_signed, certs_recipients, content_enc_alg=content_enc_alg, key_enc_alg=key_enc_alg
    )

    if passed_as_bytes:
        return message_signed_enveloped.as_bytes()
    elif passed_as_str:
        return message_signed_enveloped.as_string()
    else:
        return message_signed_enveloped
