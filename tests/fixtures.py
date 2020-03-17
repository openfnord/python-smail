# _*_ coding: utf-8 _*_
from email.mime.text import MIMEText
from email.utils import formatdate


def get_plain_text_message():
    message = MIMEText("This a plain text body!")
    message['Date'] = formatdate(localtime=True)
    message['From'] = "bar@example.com"
    message['To'] = "foo@example.com"
    message['Subject'] = "Plain Text Message"

    return message
