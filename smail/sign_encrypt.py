from copy import deepcopy
from email import message_from_bytes, message_from_string
from email.header import Header

from smail.encrypt import encrypt_message
from smail.sign import sign_message


def _pop_headers(msg, blacklist=None):
    """Removes headers from message and removes list of removed headers.

    Args:
        msg (:obj:`email.message.Message`): The message object to sign and encrypt.
        blacklist (:obj:`list` of `str`):

    Returns:
        list: removed headers

    Attention:
        side effect:  will remove headers from passed in `msg`

    Attention:
        duplicate headers are not supported at this point

    """

    blacklisted_headers = set()
    blacklisted_headers.add('content-type')
    blacklisted_headers.add('mime-version')

    if blacklist:
        for item in blacklist:
            blacklisted_headers.add(item.lower())

    headers = []
    for header in msg.items():
        # print("processing: {} - {}".format(header[0], header[1]))
        if header[0].lower() in blacklisted_headers:
            continue

        if isinstance(header[0], Header):
            print("\n\n---\nFound a header!\n---\n\n")
        headers.append(header)
        msg.__delitem__(header[0])

    return headers


def sign_and_encrypt_message(message, key_signer, cert_signer, certs_recipients,
                             digest_alg="sha256", sig_alg="rsa",
                             attrs=True, prefix="",
                             content_enc_alg="aes256_cbc", key_enc_alg="rsaes_pkcs1v15"):
    """Takes a message, signs and encrypts it and returns a new signed and encrypted message object.

    Args:
        message (:obj:`email.message.Message`): The message object to sign and encrypt.
        key_signer (:obj:`asn1crypto.keys.PrivateKeyInfo`): Private key used to sign the
            message.
        cert_signer (:obj:`asn1crypto.x509.Certificate`): Certificate/Public Key
            (belonging to Private Key) that will be included in the signed message.
        certs_recipients (:obj:`list` of :obj:`asn1crypto.x509.Certificate`): List of
            certificates for which the message should be encrypted.
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

    # Extract the message payload without conversion, & the outermost MIME header / Content headers. This allows
    # the MIME content to be rendered for any outermost MIME type incl. multipart
    copied_msg = deepcopy(message)

    popped_headers = _pop_headers(copied_msg)

    # ToDo(frennkie) payload not used anymore.. does this still work for MultiPart?!
    # if isinstance(copied_msg, MIMEMultipart):
    #     payload = b''.join([x.as_bytes() for x in copied_msg.get_payload()])
    # elif isinstance(copied_msg, MIMEText):
    #     # ensure that we have bytes
    #     payload = copied_msg.get_payload().encode()
    # elif isinstance(copied_msg, str):
    #     payload = copied_msg.encode()
    # else:
    #     payload = copied_msg.as_bytes()

    # print("---")
    # print("Payload")
    # print(type(payload))
    # print(payload)
    # print("---")

    # payload_signed = sign_message(payload, key_signer, cert_signer)
    # message_signed = email.message_from_bytes(payload_signed)

    message_signed = sign_message(copied_msg, key_signer, cert_signer,
                                  digest_alg=digest_alg, sig_alg=sig_alg,
                                  attrs=attrs, prefix=prefix)

    # print("---")
    # print("Signed")
    # print(type(message_signed))
    # print(message_signed)
    # print("---")

    for header in popped_headers:
        try:
            message_signed.replace_header(header[0], str(header[1]))
        except KeyError:
            message_signed.add_header(header[0], str(header[1]))

    # print("---")
    # print("Signed+Headers")
    # print(type(message_signed))
    # print(message_signed)
    # print("---")

    message_signed_enveloped = encrypt_message(message_signed, certs_recipients,
                                               content_enc_alg=content_enc_alg, key_enc_alg=key_enc_alg)

    # print("---")
    # print("Signed+Enveloped")
    # print(type(message_signed_enveloped))
    # print(message_signed_enveloped)
    # print("---")

    if passed_as_bytes:
        return message_signed_enveloped.as_bytes()
    elif passed_as_str:
        return message_signed_enveloped.as_string()
    else:
        return message_signed_enveloped
