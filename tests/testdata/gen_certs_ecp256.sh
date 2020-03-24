#!/bin/bash

if [ $# -eq 0 ]
  then
    OPENSSL="/usr/bin/openssl"
else
    OPENSSL="$1"
fi

echo "Generate certificates: EC (eliptic curve) p256-1"
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
echo "subjectAltName = email:AliceECp256@example.com" >> ee_alice.ext
echo "extendedKeyUsage = clientAuth,emailProtection" >> ee_alice.ext

echo "basicConstraints = critical,CA:FALSE" > ee_bob.ext
echo "keyUsage = critical,digitalSignature,keyEncipherment" >> ee_bob.ext
echo "authorityKeyIdentifier = keyid,issuer" >> ee_bob.ext
echo "subjectKeyIdentifier = hash" >> ee_bob.ext
echo "subjectAltName = email:BobECp256@example.com" >> ee_bob.ext
echo "extendedKeyUsage = clientAuth,emailProtection" >> ee_bob.ext

echo "basicConstraints = critical,CA:FALSE" > ee_diane.ext
echo "keyUsage = critical,digitalSignature,keyEncipherment" >> ee_diane.ext
echo "authorityKeyIdentifier = keyid,issuer" >> ee_diane.ext
echo "subjectKeyIdentifier = hash" >> ee_diane.ext
echo "subjectAltName = email:DianeECp256@example.com" >> ee_diane.ext
echo "extendedKeyUsage = clientAuth,emailProtection" >> ee_diane.ext


# Generate EC private key for EC CA
# The named curve is P-256 in NIST (or prime256v1 in ANSI X9.62, or secp256r1 in SECG)
${OPENSSL} genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out CarlPrivECp256Self.pem

# Generate certificate signing request for EC CA
${OPENSSL} req -new -key CarlPrivECp256Self.pem -subj "/CN=CarlECp256" -sha256 -out CarlECp256Self.csr

# Generate EC CA based on the above CSR, and sign it with the above EC CA key
${OPENSSL} x509 -extfile ca.ext -req -CAcreateserial -days 18250 -in CarlECp256Self.csr -sha256 -signkey CarlPrivECp256Self.pem -out CarlECp256Self.pem


# Generate EC private key for EC EE (Alice)
${OPENSSL} genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out AlicePrivECp256.pem

# Generate certificate signing request for EC EE
${OPENSSL} req -new -key AlicePrivECp256.pem -subj "/CN=AliceECp256" -sha256 -out AliceECp256.csr

# Generate EC EE based on the above CSR, and sign it with the above EC CA
${OPENSSL} x509 -extfile ee_alice.ext -req -CAcreateserial -days 14600 -in AliceECp256.csr -sha256 -CA CarlECp256Self.pem -CAkey CarlPrivECp256Self.pem -out AliceECp256.pem


# Generate EC private key for EC EE (Bob)
${OPENSSL} genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out BobPrivECp256.pem

# Generate certificate signing request for EC EE
${OPENSSL} req -new -key BobPrivECp256.pem -subj "/CN=BobECp256" -sha256 -out BobECp256.csr

# Generate EC EE based on the above CSR, and sign it with the above EC CA
${OPENSSL} x509 -extfile ee_bob.ext -req -CAcreateserial -days 14600 -in BobECp256.csr -sha256 -CA CarlECp256Self.pem -CAkey CarlPrivECp256Self.pem -out BobECp256.pem


# Generate EC private key for EC EE (Diane)
${OPENSSL} genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out DianePrivECp256.pem

# Generate certificate signing request for EC EE
${OPENSSL} req -new -key DianePrivECp256.pem -subj "/CN=DianeECp256" -sha256 -out DianeECp256.csr

# Generate EC EE based on the above CSR, and sign it with the above EC CA
${OPENSSL} x509 -extfile ee_diane.ext -req -CAcreateserial -days 14600 -in DianeECp256.csr -sha256 -CA CarlECp256Self.pem -CAkey CarlPrivECp256Self.pem -out DianeECp256.pem

# Clean up CSRs, Ext and SRL                                                                                                               │
rm AliceECp256.csr ee_alice.ext BobECp256.csr ee_bob.ext CarlECp256Self.csr CarlECp256Self.srl ca.ext DianeECp256.csr ee_diane.ext
