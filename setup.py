#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open('README.rst') as f:
    README = f.read()

with open('LICENSE') as f:
    LICENSE = f.read()

with open('smail/version.py') as f:
    __version__ = ''
    exec(f.read())  # set __version__

test_requires = ['pytest', 'pytest-flake8', 'pytest-cov']
setup(
    name='smail',
    version=__version__,
    description='Python S/MIME Toolkit',
    long_description=README,
    url='https://gitlab.com/rhab/python-smail',
    author='Rboert Habermann',
    author_email='mail@rhab.de',
    license='Apache License (2.0)',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Operating System :: OS Independent',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Software Development :: Libraries',
        'Topic :: Communications :: Email',
        'Topic :: Security :: Cryptography',
    ],
    keywords='smime cryptography email',
    packages=find_packages(exclude=['smail/test', 'smail/crypto/testdata',
                                    'smail/crypto/tools', '*_test.py']),
    platforms=["all"],
    install_requires=['cryptography', 'asn1crypto', 'six'],
    setup_requires=['pytest-runner'],
    tests_require=test_requires,
    test_suite='tests',
    extras_require={
        'test': test_requires
    },
    zip_safe=False,
)
