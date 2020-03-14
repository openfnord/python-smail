#!/usr/bin/env python
# _*_ coding: utf-8 _*_
import os
import subprocess
from email import message_from_string
from tempfile import mkstemp

from smail.encrypt import encrypt

openssl_binary = os.environ.get("OPENSSL_BINARY", None)
if not openssl_binary:
    openssl_binary = "openssl"


def get_cmd_output(args):
    try:
        result = subprocess.check_output(args, stderr=subprocess.STDOUT)

    except subprocess.CalledProcessError as err:
        raise Exception("Running shell command \"{}\" caused "
                        "error: {} (RC: {}".format(err.cmd, err.output, err.returncode))

    except Exception as err:
        raise Exception("Error: {}".format(err))

    return result.decode()


def assert_message_to_carl(settings, algorithm):
    message = [
        'From: "Alice" <alice@foo.com>',
        'To: "Carl" <carl@bar.com>',
        "Subject: A message from python",
        "",
        "Now you see me.",
    ]
    with open(settings['carl_public_certificate']) as cert:
        result = encrypt("\n".join(message), cert.read(), algorithm=algorithm)

    fd, tmp_file = mkstemp()
    os.write(fd, result.encode())

    cmd = [
        openssl_binary,
        "smime",
        "-decrypt",
        "-in",
        tmp_file,
        "-inkey",
        settings['carl_private_certificate'],
    ]
    cmd_output = get_cmd_output(cmd)
    private_message = message_from_string(cmd_output)
    payload = private_message.get_payload().splitlines()

    assert "Now you see me." == payload[len(payload) - 1]

    return 1


def test_message_to_carl_aes256_cbc(base_settings):
    settings = base_settings
    assert assert_message_to_carl(settings, "aes256_cbc") == 1


def test_message_to_carl_aes192_cbc(base_settings):
    settings = base_settings
    assert assert_message_to_carl(settings, "aes192_cbc") == 1


def test_message_to_carl_aes128_cbc(base_settings):
    settings = base_settings
    assert assert_message_to_carl(settings, "aes128_cbc") == 1


def assert_message_with_breaks_to_carl(settings, algorithm):
    message = [
        'From: "Alice" <alice@foo.com>',
        'To: "Carl" <carl@bar.com>',
        "Subject: A message from python",
        "",
        """Hello,

this is a message with line breaks.
And some text.

Goodbye!
""",
    ]
    with open(settings['carl_public_certificate']) as cert:
        result = encrypt("\n".join(message), cert.read(), algorithm=algorithm)

    fd, tmp_file = mkstemp()
    os.write(fd, result.encode())

    cmd = [
        openssl_binary,
        "smime",
        "-decrypt",
        "-in",
        tmp_file,
        "-inkey",
        settings['carl_private_certificate'],
    ]
    cmd_output = get_cmd_output(cmd)
    private_message = message_from_string(cmd_output)

    assert """Hello,

this is a message with line breaks.
And some text.

Goodbye!
""" == private_message.get_payload()

    return 1


def test_message_with_breaks_to_carl_aes256_cbc(base_settings):
    settings = base_settings
    assert assert_message_with_breaks_to_carl(settings, "aes256_cbc") == 1
