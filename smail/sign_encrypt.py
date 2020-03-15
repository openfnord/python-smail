import email
from email import message_from_bytes, message_from_string
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from smail import encrypt
from smail.sign import sign


def _pop_headers(msg, blacklist=None):
    """ remove and return headers

    Attention: side effects - this will remove headers from `msg`
    Attention: duplicate headers are not supported at this point

    :param msg: `email.message.Message`
    :return: list of `tuples`
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


def sign_and_encrypt(msg, sign_cert, sign_key, recipients_certs, algorithm="aes256_cbc"):
    # Get the message content. This could be a string, bytes or a message object
    passed_as_str = isinstance(msg, str)

    if passed_as_str:
        msg = message_from_string(msg)

    passed_as_bytes = isinstance(msg, bytes)
    if passed_as_bytes:
        msg = message_from_bytes(msg)

    popped_headers = _pop_headers(msg)

    if isinstance(msg, MIMEMultipart):
        payload = b''.join([x.as_bytes() for x in msg.get_payload()])
    elif isinstance(msg, MIMEText):
        # ensure that we have bytes
        payload = msg.get_payload().encode()
    elif isinstance(msg, str):
        payload = msg.encode()
    else:
        payload = msg.as_bytes()

    # print("---")
    # print("Payload")
    # print(type(payload))
    # print(payload)
    # print("---")

    payload_signed = sign(payload, sign_cert, sign_key)
    msg_signed = email.message_from_bytes(payload_signed)

    # print("---")
    # print("Signed")
    # print(type(msg_signed))
    # print(msg_signed)
    # print("---")

    for header in popped_headers:
        try:
            msg_signed.replace_header(header[0], header[1])
        except KeyError:
            msg_signed.add_header(header[0], header[1])

    # print("---")
    # print("Signed+Headers")
    # print(type(msg_signed))
    # print(msg_signed)
    # print("---")

    with open(recipients_certs[0], 'rb') as pem:  # TODO(frennkie) allow multiple
        msg_signed_enveloped = encrypt(msg_signed, pem.read(), algorithm=algorithm)

    # print("---")
    # print("Signed+Enveloped")
    # print(type(msg_signed_enveloped))
    # print(msg_signed_enveloped)
    # print("---")

    if passed_as_bytes:
        return msg_signed_enveloped.as_bytes()
    elif passed_as_str:
        return msg_signed_enveloped.as_string()
    else:
        return msg_signed_enveloped
