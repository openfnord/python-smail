# _*_ coding: utf-8 _*_
import os
from email.mime.text import MIMEText
from email.utils import formatdate


def get_plain_text_message():
    message = MIMEText("This a plain text body!")
    message['Date'] = formatdate(localtime=True)
    # message['From'] = os.environ.get("SMAIL_FROM_ADDR_1", "from_addr_1@example.com")
    message['From'] = os.environ.get("SMAIL_FROM_ADDR_1", "AliceRSA@example.com")
    message['From'] = "AliceRSA@example.com"
    message['To'] = os.environ.get("SMAIL_TO_ADDR_1", "to_addr_1@example.com")
    message['Subject'] = "Plain Text Message"

    return message
