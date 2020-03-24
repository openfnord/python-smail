#!/bin/bash

if [ $# -eq 0 ]
  then
    OPENSSL="/usr/bin/openssl"
else
    OPENSSL="$1"
fi

echo "Generate certificates: RSA 2048 bit"
echo "Using openssl binary: ${OPENSSL}"
echo ""


# Generate X.509 version 3 extension file for CA
echo "subjectKeyIdentifier = hash" > ca.ext
echo "authorityKeyIdentifier = keyid" >> ca.ext
echo "basicConstraints = critical,CA:TRUE" >> ca.ext

# Generate X.509 version 3 extension file for EE
echo "basicConstraints = critical,CA:FALSE" > ee_alice.ext
echo "keyUsage = critical,digitalSignature,keyEncipherment" >> ee_alice.ext
echo "authorityKeyIdentifier = keyid,issuer" >> ee_alice.ext
echo "subjectKeyIdentifier = hash" >> ee_alice.ext
echo "subjectAltName = email:AliceRSA2048@example.com" >> ee_alice.ext
echo "extendedKeyUsage = clientAuth,emailProtection" >> ee_alice.ext

echo "basicConstraints = critical,CA:FALSE" > ee_bob.ext
echo "keyUsage = critical,digitalSignature,keyEncipherment" >> ee_bob.ext
echo "authorityKeyIdentifier = keyid,issuer" >> ee_bob.ext
echo "subjectKeyIdentifier = hash" >> ee_bob.ext
echo "subjectAltName = email:BobRSA2048@example.com" >> ee_bob.ext
echo "extendedKeyUsage = clientAuth,emailProtection" >> ee_bob.ext

echo "basicConstraints = critical,CA:FALSE" > ee_diane.ext
echo "keyUsage = critical,digitalSignature,keyEncipherment" >> ee_diane.ext
echo "authorityKeyIdentifier = keyid,issuer" >> ee_diane.ext
echo "subjectKeyIdentifier = hash" >> ee_diane.ext
echo "subjectAltName = email:DianeRSA2048@example.com" >> ee_diane.ext
echo "extendedKeyUsage = clientAuth,emailProtection" >> ee_diane.ext


# Generate RSA private key for RSA CA
# The key size is 2048; the exponent is 65537
${OPENSSL} genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out CarlPrivRSA2048Self.pem

# Generate certificate signing request for RSA CA
${OPENSSL} req -new -key CarlPrivRSA2048Self.pem -subj "/CN=CarlRSA2048" -sha256 -out CarlRSA2048Self.csr

# Generate RSA CA based on the above CSR, and sign it with the above RSA CA key
${OPENSSL} x509 -extfile ca.ext -req -CAcreateserial -days 18250 -in CarlRSA2048Self.csr -sha256 -signkey CarlPrivRSA2048Self.pem -out CarlRSA2048Self.pem


# Generate RSA private key for RSA EE (Alice)
${OPENSSL} genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out AlicePrivRSA2048.pem

# Generate certificate signing request for RSA EE
${OPENSSL} req -new -key AlicePrivRSA2048.pem -subj "/CN=AliceRSA2048" -sha256 -out AliceRSA2048.csr

# Generate RSA EE based on the above CSR, and sign it with the above RSA CA
${OPENSSL} x509 -extfile ee_alice.ext -req -CAcreateserial -days 14600 -in AliceRSA2048.csr -sha256 -CA CarlRSA2048Self.pem -CAkey CarlPrivRSA2048Self.pem -out AliceRSA2048.pem


# Generate RSA private key for RSA EE (Bob)
${OPENSSL} genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out BobPrivRSA2048.pem

# Generate certificate signing request for RSA EE
${OPENSSL} req -new -key BobPrivRSA2048.pem -subj "/CN=BobRSA2048" -sha256 -out BobRSA2048.csr

# Generate RSA EE based on the above CSR, and sign it with the above RSA CA
${OPENSSL} x509 -extfile ee_bob.ext -req -CAcreateserial -days 14600 -in BobRSA2048.csr -sha256 -CA CarlRSA2048Self.pem -CAkey CarlPrivRSA2048Self.pem -out BobRSA2048.pem


# Generate RSA private key for RSA EE (Diane)
${OPENSSL} genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out DianePrivRSA2048.pem

# Generate certificate signing request for RSA EE
${OPENSSL} req -new -key DianePrivRSA2048.pem -subj "/CN=DianeRSA2048" -sha256 -out DianeRSA2048.csr

# Generate RSA EE based on the above CSR, and sign it with the above RSA CA
${OPENSSL} x509 -extfile ee_bob.ext -req -CAcreateserial -days 14600 -in DianeRSA2048.csr -sha256 -CA CarlRSA2048Self.pem -CAkey CarlPrivRSA2048Self.pem -out DianeRSA2048.pem

# Clean up CSRs, Ext and SRL                                                                                                               │
rm AliceRSA2048.csr ee_alice.ext BobRSA2048.csr ee_bob.ext CarlRSA2048Self.csr CarlRSA2048Self.srl ca.ext DianeRSA2048.csr ee_diane.ext
