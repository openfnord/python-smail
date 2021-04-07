# coding: utf-8

import os
from abc import ABCMeta
from abc import abstractmethod

from oscrypto import symmetric, asymmetric


class UnsupportedAlgorithmError(Exception):
    """
    An exception indicating that an unsupported cipher algorithm was specified
    """

    pass


def _get_content_algorithm(alg):
    try:
        algorithm = _CONTENT_ALGORITHMS[alg]

        # Init with optional parameters
        return algorithm[0](**algorithm[1])
    except KeyError:
        raise UnsupportedAlgorithmError("selected algorithm \"{}\" not in: "
                                        "{}".format(alg, ", ".join(_CONTENT_ALGORITHMS.keys())))


def _get_key_algorithm(alg):
    try:
        return _KEY_ALGORITHMS[alg]
    except KeyError:
        raise UnsupportedAlgorithmError("selected algorithm \"{}\" not in: "
                                        "{}".format(alg, ", ".join(_KEY_ALGORITHMS.keys())))


def encrypt_content(alg, data):
    # Get the algorithm
    algorithm = _get_content_algorithm(alg)

    # Generate key and iv
    key = os.urandom(algorithm.key_size)
    iv = os.urandom(algorithm.iv_size)
    _, ciphertext = algorithm.encryption_method(key, data.encode('utf-8'), iv)

    return key, iv, ciphertext


def decrypt_content(alg, key, iv, ciphertext):
    # Get the algorithm
    algorithm = _get_content_algorithm(alg)

    return algorithm.decryption_method(key, ciphertext, iv)


def encrypt_key(alg, public_key, session_key):
    # Get the algorithm
    algorithm = _get_key_algorithm(alg)['encrypt']

    # Encrypt session key
    return algorithm(public_key, session_key)


def decrypt_key(alg, private_key, encrypted_key):
    # Get the algorithm
    algorithm = _get_key_algorithm(alg)['decrypt']

    # Decrypt session key
    return algorithm(private_key, encrypted_key)


class EncryptionCipher:
    __metaclass__ = ABCMeta

    @property
    @abstractmethod
    def encryption_method(self):
        return NotImplemented

    @property
    @abstractmethod
    def decryption_method(self):
        return NotImplemented

    @property
    @abstractmethod
    def key_size(self):
        return NotImplemented

    @property
    @abstractmethod
    def iv_size(self):
        return NotImplemented


class AesCbc(EncryptionCipher):
    def __init__(self, key_size):
        self._key_size = key_size

    @property
    def encryption_method(self):
        return symmetric.aes_cbc_pkcs7_encrypt

    @property
    def decryption_method(self):
        return symmetric.aes_cbc_pkcs7_decrypt

    @property
    def key_size(self):
        return self._key_size

    @property
    def iv_size(self):
        return 16


class TripleDes(EncryptionCipher):
    @property
    def encryption_method(self):
        return symmetric.tripledes_cbc_pkcs5_encrypt

    @property
    def decryption_method(self):
        return symmetric.tripledes_cbc_pkcs5_decrypt

    @property
    def key_size(self):
        return 24

    @property
    def iv_size(self):
        return 8


class RC2(EncryptionCipher):
    @property
    def encryption_method(self):
        return symmetric.rc2_cbc_pkcs5_encrypt

    @property
    def decryption_method(self):
        return symmetric.rc2_cbc_pkcs5_decrypt

    @property
    def key_size(self):
        return 8

    @property
    def iv_size(self):
        return 8


_CONTENT_ALGORITHMS = {
    "tripledes_3key": [TripleDes, {}],
    "aes128_cbc": [AesCbc, {'key_size': 16}],
    "aes256_cbc": [AesCbc, {'key_size': 32}],
    "rc2": [RC2, {}]
}

_KEY_ALGORITHMS = {
    "rsaes_pkcs1v15": {'encrypt': asymmetric.rsa_pkcs1v15_encrypt, 'decrypt': asymmetric.rsa_pkcs1v15_decrypt},
    # rsa is mapped to rsaes_pkcs1v15 in asn1crypto
    "rsa": {'encrypt': asymmetric.rsa_pkcs1v15_encrypt, 'decrypt': asymmetric.rsa_pkcs1v15_decrypt}
}
