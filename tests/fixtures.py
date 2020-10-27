# _*_ coding: utf-8 _*_
import os
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
from pathlib import Path


def get_plain_text_message():
    message = MIMEText("This a plain text body!")
    message['Date'] = formatdate(localtime=True)
    # message['From'] = os.environ.get("SMAIL_FROM_ADDR_1", "from_addr_1@example.com")
    # message['From'] = os.environ.get("SMAIL_FROM_ADDR_1", "AliceRSA@example.com")
    message['From'] = "AliceRSA@example.com"
    message['To'] = os.environ.get("SMAIL_TO_ADDR_1", "to_addr_1@example.com")
    message['Subject'] = "Plain Text Message"

    return message


def get_message(send_from: str = "AliceRSA@example.com",
                send_to: list = None,
                subject: str = "Plain Text Message",
                body: str = "Body Content",
                files: list = None):
    if send_to is None:
        send_to = [os.environ.get("SMAIL_TO_ADDR_1", "to_addr_1@example.com")]

    message = MIMEMultipart()
    message['From'] = send_from
    message['To'] = COMMASPACE.join(send_to)
    message['Date'] = formatdate(localtime=True)
    message['Subject'] = subject

    message.attach(MIMEText(body))

    for path in files:
        part = MIMEBase('application', "octet-stream")
        with open(path, 'rb') as file:
            part.set_payload(file.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition',
                        'attachment; filename="{}"'.format(Path(path).name))
        message.attach(part)

    return message
