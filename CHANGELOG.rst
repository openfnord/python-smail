=======
CHANGES
=======

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

0.x.0 (unreleased)
------------------
- tbd


0.10.0 (2024-04-07)
-------------------

- change: switch default branch to main
- add: test cases using attachments
- fix: header Content-Transfer-Encoding no longer removed in sign_and_encrypt_message
- cleanup: duplicate code for header extraction from sign_message and encrypt_message moved to utils,
  make use of normalize_line_endings to ensure that signed and encrypted messages show as valid in Microsoft Outlook

0.9.0 (2020-10-17)
------------------

- add: include_cert_signer (bool) to sign_message() which indicates whether the signing
  certificate should be included
- add: additional_certs (list) to sign_message() which allows for additional certificates
  (e.g. Intermediate CAs) to be added
- change: simplify MIME encoding (replace custom function "wrap_lines")
- remove: smail.utils.wrap_lines

0.8.0 (2020-09-20)
------------------

- fix: issue #6 corrupted MIMEMultipart alternative signing

0.7.0 (2020-03-29)
------------------

- change: signature for sign, encrypt, sign_and_encrypt

0.6.0 (2020-03-28)
------------------

- add: documentation

0.5.1 (2020-03-17)
------------------

- remove: outdated parts of README.rst

0.5.0 (2020-03-17)
------------------

- add: rewrite of README.rst
- add: unittests

0.4.0 (2020-03-16)
------------------

- add: sign_and_encrypt

0.3.0 (2020-03-14)
------------------

- remove: six

0.2.2 (2020-03-14)
------------------

- add: implement automated tests
- add: encrypt
- add: sign

0.1.0 (2020-03-14)
------------------

- Initial release.
