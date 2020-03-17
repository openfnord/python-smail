import email
from email import message_from_bytes, message_from_string
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from smail.encrypt import encrypt_message
from smail.sign import sign_message


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


def sign_and_encrypt_message(message, cert_signer, key_signer, certs_recipients, algorithm="aes256_cbc"):
    # Get the message content. This could be a string, bytes or a message object
    passed_as_str = isinstance(message, str)
    if passed_as_str:
        message = message_from_string(message)

    passed_as_bytes = isinstance(message, bytes)
    if passed_as_bytes:
        message = message_from_bytes(message)

    popped_headers = _pop_headers(message)

    if isinstance(message, MIMEMultipart):
        payload = b''.join([x.as_bytes() for x in message.get_payload()])
    elif isinstance(message, MIMEText):
        # ensure that we have bytes
        payload = message.get_payload().encode()
    elif isinstance(message, str):
        payload = message.encode()
    else:
        payload = message.as_bytes()

    # print("---")
    # print("Payload")
    # print(type(payload))
    # print(payload)
    # print("---")

    payload_signed = sign_message(payload, cert_signer, key_signer)
    message_signed = email.message_from_bytes(payload_signed)

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

    message_signed_enveloped = encrypt_message(message_signed, certs_recipients, algorithm=algorithm)

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
