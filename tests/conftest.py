# _*_ coding: utf-8 _*_
import os
from email.mime.text import MIMEText
from email.utils import formatdate

import pytest

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'testdata')
