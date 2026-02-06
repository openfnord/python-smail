# coding: utf-8

import os
from abc import ABCMeta
from abc import abstractmethod

from oscrypto import symmetric
from oscrypto import util


class EncryptionCipher:
    __metaclass__ = ABCMeta

    @abstractmethod
    def encrypt(self, data):
        return NotImplemented

    @property
    def session_key(self):
        return NotImplemented

    @property
    def parameters(self):
        return NotImplemented


class AesCbc(EncryptionCipher):
    algorithm = None
    key_size = None

    def __init__(self, algorithm, key_size):
        self.algorithm = algorithm
        self.key_size = key_size

        #improve random numbers 
        #self._session_key = os.urandom(self.key_size)
        #self._iv = os.urandom(16)  # fixed size of 16 bytes (block size) for initialization vector

        #https://github.com/wbond/oscrypto/blob/master/docs/util.md
        self._session_key = util.rand_bytes(self.key_size)
        self._iv = util.rand_bytes(16)  # fixed size of 16 bytes (block size) for initialization vector


    def encrypt(self, data):
        _, ciphertext = symmetric.aes_cbc_pkcs7_encrypt(self._session_key, data.encode("utf-8"), self._iv)

        return {
            "content_type": "data",
            "content_encryption_algorithm": {
                "algorithm": self.algorithm,
                "parameters": self._iv,
            },
            "encrypted_content": ciphertext,
        }

    @property
    def session_key(self):
        return self._session_key

    @property
    def parameters(self):
        return self._iv


class TripleDes(EncryptionCipher):
    algorithm = None
    key_size = None

    def __init__(self, algorithm, key_size):
        self.algorithm = algorithm
        self.key_size = key_size
        
        #improve random numbers 
        #self._session_key = os.urandom(self.key_size)
        #self._iv = os.urandom(8)  # fixed size of 8 bytes for initialization vector

        #https://github.com/wbond/oscrypto/blob/master/docs/util.md
        self._session_key = util.rand_bytes(self.key_size)
        self._iv = util.rand_bytes(8)  # fixed size of 8 bytes for initialization vector

    def encrypt(self, data):
        _, ciphertext = symmetric.tripledes_cbc_pkcs5_encrypt(self._session_key, data.encode("utf-8"), self._iv)

        return {
            "content_type": "data",
            "content_encryption_algorithm": {
                "algorithm": self.algorithm,
                "parameters": self._iv,
            },
            "encrypted_content": ciphertext,
        }

    @property
    def session_key(self):
        return self._session_key

    @property
    def parameters(self):
        return self._iv
