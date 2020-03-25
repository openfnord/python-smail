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

test_requires = ['coverage', 'flake8', 'tox']
setup(
    name='python-smail',
    version=__version__,
    description='Simple S/MIME e-mails with Python3',
    long_description=README,
    url='https://gitlab.com/rhab/python-smail',
    author='Robert Habermann',
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
        'Programming Language :: Python :: 3.8',
        'Topic :: Software Development :: Libraries',
        'Topic :: Communications :: Email',
        'Topic :: Security :: Cryptography',
    ],
    keywords='smime cryptography email S/MIME encrypt sign',
    packages=find_packages(exclude=['tests', '*_test.py', 'test_*.py']),
    platforms=["all"],
    install_requires=['asn1crypto', 'oscrypto'],
    setup_requires=['pytest-runner'],
    tests_require=test_requires,
    test_suite='tests',
    extras_require={
        'test': test_requires
    },
    zip_safe=False,
)
