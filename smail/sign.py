# _*_ coding: utf-8 _*_
from copy import deepcopy
from email import message_from_string, message_from_bytes

from cryptography import x509
from cryptography.hazmat.backends import default_backend as cryptography_backend
from cryptography.hazmat.bindings.openssl.binding import Binding as SSLBinding
from cryptography.hazmat.primitives import serialization


def sign_message(message, cert_signer, key_signer):
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

    headers = {}
    # besides some special ones (e.g. Content-Type) remove all headers before encrypting the body content
    for hdr_name in list(copied_msg.keys()):
        if hdr_name in ["Content-Type", "MIME-Version", "Content-Transfer-Encoding"]:
            continue

        values = copied_msg.get_all(hdr_name)
        if values:
            del copied_msg[hdr_name]
            headers[hdr_name] = values

    content = copied_msg.as_bytes()

    # load cert & keys
    x509_cert = x509.load_pem_x509_certificate(cert_signer, cryptography_backend())
    private_key = serialization.load_pem_private_key(key_signer, None, cryptography_backend())

    # sign bytes and parse signed message
    signed_bytes = sign_bytes(content, x509_cert, private_key)
    signed_message = message_from_bytes(signed_bytes)

    # add original headers
    for hrd, values in headers.items():
        for val in values:
            try:
                signed_message.replace_header(hrd, str(val))
            except KeyError:
                signed_message.add_header(hrd, str(val))

    if passed_as_bytes:
        return signed_message.as_bytes()
    elif passed_as_str:
        return signed_message.as_string()
    else:
        return signed_message


def sign_bytes(byte_string, cert, key):
    """sign_bytes

    writen by kyrofa under Apache License 2.0 in:
    https://github.com/ros2/sros2/pull/129/commits/cfb4381fc1bc45a4f3ea9aa7e92f5228c08a2d04

    """
    # Using two flags here to get the output required:
    #   - PKCS7_DETACHED: Use cleartext signing
    #   - PKCS7_TEXT: Set the MIME headers for text/plain <- disabled to allow text/html
    # flags = 0
    flags = SSLBinding.lib.PKCS7_DETACHED
    # flags |= SSLBinding.lib.PKCS7_TEXT

    # Convert the byte string into a buffer for SSL
    bio_in = SSLBinding.lib.BIO_new_mem_buf(byte_string, len(byte_string))
    try:
        pkcs7 = SSLBinding.lib.PKCS7_sign(
            cert._x509, key._evp_pkey, SSLBinding.ffi.NULL, bio_in, flags)
    finally:
        # Free the memory allocated for the buffer
        SSLBinding.lib.BIO_free(bio_in)

    # PKCS7_sign consumes the buffer; allocate a new one again to get it into the final document
    bio_in = SSLBinding.lib.BIO_new_mem_buf(byte_string, len(byte_string))
    try:
        # Allocate a buffer for the output document
        bio_out = SSLBinding.lib.BIO_new(SSLBinding.lib.BIO_s_mem())
        try:
            # Write the final document out to the buffer
            SSLBinding.lib.SMIME_write_PKCS7(bio_out, pkcs7, bio_in, flags)

            # Copy the output document back to python-managed memory
            result_buffer = SSLBinding.ffi.new('char**')
            buffer_length = SSLBinding.lib.BIO_get_mem_data(bio_out, result_buffer)
            output = SSLBinding.ffi.buffer(result_buffer[0], buffer_length)[:]
        finally:
            # Free the memory required for the output buffer
            SSLBinding.lib.BIO_free(bio_out)
    finally:
        # Free the memory allocated for the input buffer
        SSLBinding.lib.BIO_free(bio_in)

    return output
