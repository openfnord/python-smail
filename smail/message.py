import os
from copy import deepcopy
from email import encoders, message_from_string, message_from_bytes
from email.header import Header
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, formataddr
from email.policy import default

COMMASPACE = ', '


def make_msg(sender_addr, sender_name=None,
             recipients=None, subject=None,
             text=None, html=None,
             img_list=None, attachments=None):
    """Creates and returns a message

    Args:
        sender_addr (str): The sender address (e.g. alice@example.com).
        sender_name (str): The sender name  (e.g. Alice).
        recipients (:obj:`list` of str or :obj:`list` of :obj:`tuple` with (addr, name)): Who
            the message should go to.
        subject (str): The message subject.
        text (str): The text content to include.
        html (str): The HTML content to include.
        img_list (:obj:`list` of str`): A list of file path strings.
        attachments (:obj:`list` of str): A list of file path strings.

    Returns:
        :obj:`email.message.Message`

    """

    recipient_addr = []
    for recipient in recipients:
        if isinstance(recipient, tuple):
            recipient_addr.append(recipient[0])
        else:
            recipient_addr.append(recipient)

    msg_root = MIMEMultipart('mixed')
    msg_root['Date'] = formatdate(localtime=True)
    msg_root['From'] = formataddr((Header(sender_name, 'utf-8').encode(), sender_addr))
    msg_root['To'] = COMMASPACE.join(recipient_addr)
    msg_root['Subject'] = Header(subject, 'utf-8')
    msg_root.preamble = 'This is a multi-part message in MIME format.'

    msg_related = MIMEMultipart('related')
    msg_root.attach(msg_related)

    msg_alternative = MIMEMultipart('alternative')
    msg_related.attach(msg_alternative)

    msg_text = MIMEText(text, 'plain', 'utf-8')
    msg_alternative.attach(msg_text)

    msg_html = MIMEText(html, 'html', 'utf-8')
    msg_alternative.attach(msg_html)

    if img_list:
        for i, img in enumerate(img_list):
            if isinstance(img, tuple):
                img_path = img[0]
                content_id = img[1]
            else:
                img_path = img
                content_id = 'image{}'.format(i)

            with open(img_path, 'rb') as fp:
                msg_image = MIMEImage(fp.read())
                msg_image.add_header('Content-ID', '<{}>'.format(content_id))
                msg_image.add_header('Content-Disposition', 'inline',
                                     filename=(Header(os.path.basename(img_path), 'utf-8').encode()))
                msg_related.attach(msg_image)

    if attachments:
        for attachment in attachments:
            fname = os.path.basename(attachment)

            with open(attachment, 'rb') as f:
                msg_attach = MIMEBase('application', 'octet-stream')
                msg_attach.set_payload(f.read())
                encoders.encode_base64(msg_attach)
                msg_attach.add_header('Content-Disposition', 'attachment',
                                      filename=(Header(fname, 'utf-8').encode()))
                msg_attach.add_header('Content-ID', '<%s>' % (Header(fname, 'utf-8').encode()))
                msg_root.attach(msg_attach)

    return msg_root


def decode_message(message):
    """Decodes messages in various formats to a message object
    Args:
        message (bytes, str or :obj:`email.message.Message`): Message to be decoded.

    Returns:
        :obj:`message`: A message object, :Type:`type`: the original type the message was in
    """

    # Get the message content. This could be a string, bytes or a message object
    passed_as_str = isinstance(message, str)
    if passed_as_str:
        message = message_from_string(message, policy=default)

    passed_as_bytes = isinstance(message, bytes)
    if passed_as_bytes:
        message = message_from_bytes(message, policy=default)

    # Extract the message payload without conversion, & the outermost MIME header / Content headers. This allows
    # the MIME content to be rendered for any outermost MIME type incl. multipart
    return deepcopy(message), type(message)


def encode_message(message, message_type):
    """Encodes message objects to various types
    Args:
        message (:obj:`email.message.Message`): Message to be encoded.
        message_type (Type): Internal type to cast the message to.
        If type is not `str` or `bytes`, the original object is returned

    Returns:
        message (bytes, str or :obj:`email.message.Message`): Encoded message.
    """

    if message_type is str:
        return message.as_string()
    if message_type is bytes:
        return message.as_bytes()

    return message
