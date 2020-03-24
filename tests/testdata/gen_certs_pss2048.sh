#!/bin/bash

if [ $# -eq 0 ]
  then
    OPENSSL="/usr/bin/openssl"
else
    OPENSSL="$1"
fi

echo "Generate certificates: RSASSA-PSS 2048 bit"
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
echo "subjectAltName = email:AlicePSS2048@example.com" >> ee_alice.ext
echo "extendedKeyUsage = clientAuth,emailProtection" >> ee_alice.ext

echo "basicConstraints = critical,CA:FALSE" > ee_bob.ext
echo "keyUsage = critical,digitalSignature,keyEncipherment" >> ee_bob.ext
echo "authorityKeyIdentifier = keyid,issuer" >> ee_bob.ext
echo "subjectKeyIdentifier = hash" >> ee_bob.ext
echo "subjectAltName = email:BobPSS2048@example.com" >> ee_bob.ext
echo "extendedKeyUsage = clientAuth,emailProtection" >> ee_bob.ext

echo "basicConstraints = critical,CA:FALSE" > ee_diane.ext
echo "keyUsage = critical,digitalSignature,keyEncipherment" >> ee_diane.ext
echo "authorityKeyIdentifier = keyid,issuer" >> ee_diane.ext
echo "subjectKeyIdentifier = hash" >> ee_diane.ext
echo "subjectAltName = email:DianePSS2048@example.com" >> ee_diane.ext
echo "extendedKeyUsage = clientAuth,emailProtection" >> ee_diane.ext


# Generate RSASSA-PSS private key for RSASSA-PSS CA
# The key size is 2048; the exponent is 65537
${OPENSSL} genpkey -algorithm rsa-pss -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out CarlPrivPSS2048Self.pem

# Generate certificate signing request for RSASSA-PSS CA
${OPENSSL} req -new -key CarlPrivPSS2048Self.pem -subj "/CN=CarlPSS2048" -sha256 -out CarlPSS2048Self.csr

# Generate RSASSA-PSS CA based on the above CSR, and sign it with the above RSASSA-PSS CA key
${OPENSSL} x509 -extfile ca.ext -req -CAcreateserial -days 18250 -in CarlPSS2048Self.csr -sha256 -signkey CarlPrivPSS2048Self.pem -out CarlPSS2048Self.pem


# Generate RSASSA-PSS private key for RSASSA-PSS EE (Alice)
${OPENSSL} genpkey -algorithm rsa-pss -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out AlicePrivPSS2048.pem

# Generate certificate signing request for RSASSA-PSS EE
${OPENSSL} req -new -key AlicePrivPSS2048.pem -subj "/CN=AlicePSS2048" -sha256 -out AlicePSS2048.csr

# Generate RSASSA-PSS EE based on the above CSR, and sign it with the above RSASSA-PSS CA
${OPENSSL} x509 -extfile ee_alice.ext -req -CAcreateserial -days 14600 -in AlicePSS2048.csr -sha256 -CA CarlPSS2048Self.pem -CAkey CarlPrivPSS2048Self.pem -out AlicePSS2048.pem


# Generate RSASSA-PSS private key for RSASSA-PSS EE (Bob)
${OPENSSL} genpkey -algorithm rsa-pss -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out BobPrivPSS2048.pem

# Generate certificate signing request for RSASSA-PSS EE
${OPENSSL} req -new -key BobPrivPSS2048.pem -subj "/CN=BobPSS2048" -sha256 -out BobPSS2048.csr

# Generate RSASSA-PSS EE based on the above CSR, and sign it with the above RSASSA-PSS CA
${OPENSSL} x509 -extfile ee_bob.ext -req -CAcreateserial -days 14600 -in BobPSS2048.csr -sha256 -CA CarlPSS2048Self.pem -CAkey CarlPrivPSS2048Self.pem -out BobPSS2048.pem


# Generate RSASSA-PSS private key for RSASSA-PSS EE (Diane)
${OPENSSL} genpkey -algorithm rsa-pss -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out DianePrivPSS2048.pem

# Generate certificate signing request for RSASSA-PSS EE
${OPENSSL} req -new -key DianePrivPSS2048.pem -subj "/CN=DianePSS2048" -sha256 -out DianePSS2048.csr

# Generate RSASSA-PSS EE based on the above CSR, and sign it with the above RSASSA-PSS CA
${OPENSSL} x509 -extfile ee_diane.ext -req -CAcreateserial -days 14600 -in DianePSS2048.csr -sha256 -CA CarlPSS2048Self.pem -CAkey CarlPrivPSS2048Self.pem -out DianePSS2048.pem


# Clean up CSRs, Ext and SRL
rm AlicePSS2048.csr ee_alice.ext BobPSS2048.csr ee_bob.ext CarlPSS2048Self.csr ca.ext CarlPSS2048Self.srl DianePSS2048.csr ee_diane.ext
