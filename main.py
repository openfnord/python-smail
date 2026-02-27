#!/usr/bin/env python3

#Author for copyright purposes ludwig jaffe, 2026

#WARNING CREDENTIALS in config.ini!
"""
Tester for sending different styles email using python-smail with:
- S/MIME encryption, signing, secret text, secret attachments, 
- plain MIME attachments (logos/images/files) that remain unencrypted
- triple wrap smime (signed & encrypted and signed again)
- Mail transport:
-  SMTP over SSL (port 465) with password authentication (see config.ini)
-  STARTTLS (port 587) with password authentication (see config.ini)

Requires:
    pip install python-smail
    !use the enclosed library to get the improvements I have done!
"""

import os
import smtplib
import configparser #for parsing config.ini
from pathlib import Path #for parsing config.ini
from typing import List, Optional, Sequence, Tuple

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.application import MIMEApplication
from email import encoders
from email.utils import formatdate, make_msgid

from smail import encrypt_message, sign_and_encrypt_message, sign_message  # python-smail

#---------------
# MAGIC VALUES
#---------------

CONFIG_PATH = Path("config.ini") # path to your config containing credentials
FILE_DUMP = True  # if true, email content is written out to debug files
SHOW_PROGRESS = False  # if true, rounds of email encryption or signing will be displayed

#WHICH TEST MAILS ARE TO BE SENT?

SINGLE_ENCRYPTED_SMIME = True		#Type 3
MULTIPLE_ENCRYPTED_SMIME = True		#Type 4

SINGLE_SIGNED_SMIME = True		#Type 5
MULTIPLE_SIGNED_SMIME = True		#Type 6

SINGLE_SIGNED_ENCRYPTED_SMIME = True	#Type 7
MULTIPLE_SIGNED_ENCRYPTED_SMIME = True	#Type 8

#signed and encrypted and signed again
TRIPLE_WRAPPED_PURE_SMIME = True	#Type 11
SINGLE_TRIPLE_WRAPPED_SMIME = True	#Type 9
MULTIPLE_TRIPLE_WRAPPED_SMIME = True	#Type 10


#single signed and encrypted
PURE_SMIME = True			#Type 2

#single mixed signed and encrypted mail with unencrypted part
MIXED_SMIME_EMAIL = True		#Type 1

#rounds for multiple
MULTIPLE_CRYPT_ROUNDS = 4    #25 w/o attachments
MULTIPLE_SIGN_ROUNDS = 4  #26 w/o attachments
MULTIPLE_SIGN_CRYPT_ROUNDS = 3  #12 w/o attachments
MULTIPLE_TRIPLE_WRAPPED_ROUNDS =4  #12 w/o attachments


INCLUDE_ATTACHMENTS = True


# ----------------------------
# Configuration objects
# ----------------------------

class SMTPConfig:
    """Configuration for SMTP over SSL on port 465."""

    def __init__(
            self,
            host: str,
            port: int = 465,
            username: Optional[str] = None,
            password: Optional[str] = None,
            use_ssl: bool = True,
            use_starttls: bool = False,
            timeout: int = 30,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.use_starttls = use_starttls
        self.timeout = timeout


class SMimeConfig:
    """
    S/MIME configuration:

    - recipient_certs: list of recipient certificate paths (PEM)
    - signer_cert / signer_key: sender cert/key
    - cipher: 'AES128-CBC', 'AES192-CBC', or 'AES256-CBC'
    """

    VALID_CIPHERS = ("tripledes_3key", "aes128_cbc", "aes192_cbc" , "aes256_cbc")  # python-smail ciphers
    VALID_HASH_ALGS = ("sha256", "sha512")  # python-smail hash digest algorithms
    VALID_SIG_ALGS = ("rsa", "pss", "ecdsa")  # python-smail signature algorithms

    def __init__(
            self,
            recipient_certs: Sequence[str],
            signer_cert: Optional[str] = None,
            signer_key: Optional[str] = None,
            cipher: str = "aes256_cbc",
            hash_alg: str = "sha256",
            sig_alg: str = "rsa",
    ) -> None:
        if not recipient_certs:
            raise ValueError("At least one recipient certificate is required for S/MIME encryption.")

        cipher = cipher.lower()   #allow uppercase config values like AES256_CBC
        hash_alg = hash_alg.lower()   #allow uppercase config values like SHA256
        if cipher not in self.VALID_CIPHERS:
            raise ValueError(f"Unsupported cipher '{cipher}'. Must be one of {self.VALID_CIPHERS}.")

        if hash_alg not in self.VALID_HASH_ALGS:
            raise ValueError(f"Unsupported hash algorithm '{hash_alg}'. Must be one of {self.VALID_HASH_ALGS}.")

        if sig_alg not in self.VALID_SIG_ALGS:
            raise ValueError(f"Unsupported signature algorithm '{hash_alg}'. Must be one of {self.VALID_HASH_ALGS}.")


        self.recipient_certs = list(recipient_certs)
        self.signer_cert = signer_cert
        self.signer_key = signer_key
        self.cipher = cipher
        self.hash_alg = hash_alg
        self.sig_alg = sig_alg


# ----------------------------
# Config reader
# ----------------------------


def _str_to_bool(value: str, default: bool = True) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _split_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def load_config(path: Path = CONFIG_PATH) -> tuple[SMTPConfig, SMimeConfig | None, str, list[str]]:
    """Read SMTP-, S/MIME- und Mail-Defaults from config file.

    return: (smtp_cfg, smime_cfg_or_none, from_addr, to_addrs)
    """

    config = configparser.ConfigParser()
    read_files = config.read(path)
    if not read_files:
        raise FileNotFoundError(f"config file not found: {path}")


    # --- SMTP ---
    smtp_sec = config["smtp"] if "smtp" in config else {}

    host = smtp_sec.get("host", os.environ.get("SMTP_HOST", "mail.example.com"))
    port = int(smtp_sec.get("port", os.environ.get("SMTP_PORT", "465")))
    username = smtp_sec.get("username", os.environ.get("SMTP_USER", "mailuser@example.com"))
    password = smtp_sec.get("password", os.environ.get("SMTP_PASS", "secretmailpass"))
    use_ssl = _str_to_bool(smtp_sec.get("use_ssl", "true"))
    use_starttls = _str_to_bool(smtp_sec.get("use_starttls", "false"))
    timeout = int(smtp_sec.get("timeout", "30"))

    smtp_cfg = SMTPConfig(
    host=host,
    port=port,
    username=username,
    password=password,
    use_ssl=use_ssl,
    use_starttls=use_starttls,
    timeout=timeout,
    )
 
    # --- E-Mail-Defaults ---
    email_sec = config["email"] if "email" in config else {}
    from_addr = email_sec.get("from_addr", "sender@example.com")
    to_addrs = _split_list(email_sec.get("to_addrs", "alice@example.com, bob@example.com"))
    #TODO Attachments

    # --- S/MIME ---
    smime_cfg: SMimeConfig | None = None
    if "smime" in config:
        smime_sec = config["smime"]
        recipient_certs = _split_list(smime_sec.get("recipient_certs"))
        signer_cert = smime_sec.get("signer_cert")
        signer_key = smime_sec.get("signer_key")
        cipher = smime_sec.get("cipher", "aes256_cbc")
        hash_alg = smime_sec.get("hash_alg", "sha256")
        sig_alg = smime_sec.get("sig_alg", "rsa")

    if recipient_certs:
        smime_cfg = SMimeConfig(
        recipient_certs=recipient_certs,
        signer_cert=signer_cert,
        signer_key=signer_key,
        cipher=cipher,
        hash_alg=hash_alg,
        sig_alg=sig_alg,
    )

    return smtp_cfg, smime_cfg, from_addr, to_addrs
 
 


# ----------------------------
# Attachment helpers
# ----------------------------

def _make_inline_image(path: str, cid: Optional[str] = None) -> MIMEImage:
    """
    Create an inline image attachment (logo, image) with a Content-ID for HTML reference.
    """
    with open(path, "rb") as f:
        img = MIMEImage(f.read())
    cid_value = cid or make_msgid(domain="example.com")[1:-1]  # strip < >
    img.add_header("Content-ID", f"<{cid_value}>")
    img.add_header("Content-Disposition", "inline", filename=os.path.basename(path))
    return img


def _make_file_attachment(path: str) -> MIMEBase:
    """
    Create a generic file attachment that is safe for binary data.
    """
    with open(path, "rb") as f:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(f.read())
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment", filename=os.path.basename(path))
    return part


# ----------------------------
# Build MIME attachments
# ----------------------------

def build_mime(
        subject: str,
        from_addr: str,
        to_addrs: Sequence[str],
        text: Optional[str] = None,
        attachments: Optional[Sequence[Tuple[str, bool]]] = None,
) -> MIMEMultipart:
    """
    Build the MIME container.

    attachments: list of (path, is_image)
        - is_image=True: inline logo/image
        - is_image=False: standard attachment
    """
    mime = MIMEMultipart("mixed")
    mime["From"] = from_addr
    mime["To"] = ", ".join(to_addrs)
    mime["Subject"] = subject
    mime["Date"] = formatdate(localtime=True)

    if text:
        mime.attach(MIMEText(text, "plain", "utf-8"))

    if attachments:
        for path, is_image in attachments:
            if is_image:
                part = _make_inline_image(path)
            else:
                part = _make_file_attachment(path)
            mime.attach(part)

    return mime




# -----------------------------------
# S/MIME wrapping with python-smail
# -----------------------------------

def smime_protect(
        inner_msg: MIMEMultipart,
        config: SMimeConfig,
):
    """
    Apply S/MIME encryption or sign+encrypt using python-smail.

    Returns S/MIME part
    """
    
    # Load recipient certs
    recipient_certs_data: List[bytes] = []
    for cert_path in config.recipient_certs:
        with open(cert_path, "rb") as f:
            recipient_certs_data.append(f.read())

    # Decide whether to sign as well as encrypt
    if config.signer_cert and config.signer_key:  #sign and encrypt
        with open(config.signer_cert, "rb") as f_cert, open(config.signer_key, "rb") as f_key:
            signer_cert_bytes = f_cert.read()
            signer_key_bytes = f_key.read()

    ## DOCUMENTATION IN LIBRARY:
    ## sign_and_encrypt_message(message, key_signer, cert_signer, [certs], cipher=...)
    ## def sign_and_encrypt_message(message, key_signer, cert_signer, certs_recipients,
    ##                         digest_alg="sha256", sig_alg="rsa",
    ##                         attrs=True, prefix="",
    ##                         content_enc_alg="aes256_cbc", key_enc_alg="rsaes_pkcs1v15"):
    ## 
    ## """Takes a message, signs and encrypts it and returns a new signed and encrypted message object.
    ## 
    ## Args:
    ##     message (:obj:`email.message.Message`): The message object to sign and encrypt.
    ##
    ##    key_signer (`bytes`, `str` or :obj:`asn1crypto.keys.PrivateKeyInfo`): Private key used to
    ##        sign the message. (A byte string of file contents, a unicode string filename or an
    ##        asn1crypto.keys.PrivateKeyInfo object)
    ##    cert_signer (`bytes`, `str` or :obj:`asn1crypto.x509.Certificate`): Certificate/Public Key
    ##        (belonging to Private Key) that will be included in the signed message. (A byte string of file
    ##        contents, a unicode string filename or an asn1crypto.x509.Certificate object)
    ##    certs_recipients (:obj:`list` of `bytes`, `str` or :obj:`asn1crypto.x509.Certificate`): A
    ##        list of byte string of file contents, a unicode string filename or an
    ##        asn1crypto.x509.Certificate object for which the message should be encrypted.
    ##    digest_alg (str): Digest (Hash) Algorithm - e.g. "sha256"
    ##    sig_alg (str): Signature Algorithm
    ##    attrs (bool): Whether to include signed attributes (signing time). Default
    ##        to True
    ##    prefix (str): Content type prefix (e.g. "x-"). Default to ""
    ##    content_enc_alg (str): Content Encryption Algorithm - e.g. aes256_cbc
    ##    key_enc_alg: Key Encryption Algorithm
    ##
    ##  Returns:
    ##     :obj:`email.message.Message`: signed and encrypted message
    ##
    ##  Todo:
    ##    payload not used anymore.. does this still work for MultiPart?!
    ##
    ## """

        smime_msg = sign_and_encrypt_message(
            inner_msg,
            signer_key_bytes,
            signer_cert_bytes,
            recipient_certs_data,
            config.hash_alg, config.sig_alg, True, "",
            config.cipher, "rsaes_pkcs1v15",
	    
        )
	
    else: #encrypt only
    
        ## DOCUMENTATION IN LIBRARY:
        ##
	## encrypt_message(message, [certs], cipher=...)
        ##
	## def encrypt_message(message, certs_recipients,
        ##             content_enc_alg="aes256_cbc", key_enc_alg="rsaes_pkcs1v15", prefix=""):
        ##    """Takes a message and returns a new message with the original content as encrypted body
        ##    
        ##    Take the contents of the message parameter, formatted as in RFC 2822 (type bytes, str or
        ##    message) and encrypts them, so that they can only be read by the intended recipient
        ##    specified by pubkey.
        ##   
        ## Args:
        ##    message (bytes, str or :obj:`email.message.Message`): Message to be encrypted.
        ##    certs_recipients (:obj:`list` of `bytes`, `str` or :obj:`asn1crypto.x509.Certificate` or
        ##        :obj:`oscrypto.asymmetric.Certificate): A list of byte string of file contents, a
        ##        unicode string filename or an asn1crypto.x509.Certificate object
        ##    key_enc_alg (str): Key Encryption Algorithm
        ##    content_enc_alg (str): Content Encryption Algorithm
        ##    prefix (str): Content type prefix (e.g. "x-"). Default to ""
        ## 
        ## Returns:
        ##    :obj:`message`: The new encrypted message (type str or message, as per input).
        ## 
        ## Todo:
        ##    TODO(frennkie) cert_recipients..?!
        ##   
        ## """
        ##
	
            smime_msg = encrypt_message(
            inner_msg,
            recipient_certs_data,
            config.cipher, "rsaes_pkcs1v15", ""       
        )

    return smime_msg


#---

#produce triple wrapped smime mail according to RFC2634 section 1.1
def smime_protect_and_sign_again(
        inner_msg: MIMEMultipart,
        config: SMimeConfig,
):
    """
    Apply S/MIME sign+encrypt and sign again using python-smail.
    This should comply to RFC2634 section 1.1
    Returns S/MIME part
    """
    
    # Load recipient certs
    recipient_certs_data: List[bytes] = []
    for cert_path in config.recipient_certs:
        with open(cert_path, "rb") as f:
            recipient_certs_data.append(f.read())


    # Decide whether to sign as well as encrypt
    if config.signer_cert and config.signer_key:
        with open(config.signer_cert, "rb") as f_cert, open(config.signer_key, "rb") as f_key:
            signer_cert_bytes = f_cert.read()
            signer_key_bytes = f_key.read()


        smime_msg = sign_and_encrypt_message(
            inner_msg,
            signer_key_bytes,
            signer_cert_bytes,
            recipient_certs_data,
            config.hash_alg, config.sig_alg, True, "",
            config.cipher, "rsaes_pkcs1v15",
        )
	
        #sign again
	
        ##def sign_message(message, key_signer, cert_signer,
        ##         digest_alg='sha256', sig_alg='rsa',
        ##         attrs=True, prefix="", allow_deprecated=False,
        ##         include_cert_signer=True,
        ##         additional_certs=None,
        ##         multipart_class=MIMEMultipart):
        ##"""Takes a message, signs it and returns a new signed message object.
        ##
        ##Args:
        ##message (:obj:`email.message.Message`): The message object to sign.
        ##key_signer (`bytes`, `str` or :obj:`asn1crypto.keys.PrivateKeyInfo` or
        ##    :obj:`oscrypto.asymmetric.PrivateKey`): Private key used to sign the message. (A byte
        ##    string of file contents, a unicode string filename or an asn1crypto.keys.PrivateKeyInfo
        ##    object)
        ##cert_signer (`bytes`, `str` or :obj:`asn1crypto.x509.Certificate` or
        ##    :obj:`oscrypto.asymmetric.Certificate`): Certificate/Public Key (belonging to Private
        ##    Key) that will be included in the signed message. (A byte string of file contents, a
        ##    unicode string filename or an asn1crypto.x509.Certificate object)
        ##    digest_alg (str): Digest (Hash) Algorithm - e.g. "sha256"
        ##    sig_alg (str): Signature Algorithm
        ##    attrs (bool): Whether to include signed attributes (signing time). Default
        ##     to True
        ## prefix (str): Content type prefix (e.g. "x-"). Default to ""
        ## allow_deprecated (bool): Whether deprecated digest algorithms should be allowed.
        ## include_cert_signer (bool): Whether to include the public certificate of the signer
        ##     in the signed data. Default to True
        ## additional_certs (:obj:`list` of :obj:`asn1crypto.x509.Certificate`): List of
        ##    additional certificates to be included (e.g. Intermediate or Root CA certs).
        ## multipart_class (class): Which MIMEMultiPart class should be used.
        ##
        ##    Returns:
        ##  :obj:`email.message.Message`: signed message
        ##
        ##  """
        ##
	
	
	#sign previous signed and encrypted message
        smime_msg_signed = sign_message(
            smime_msg,
            signer_key_bytes,
            signer_cert_bytes,
            config.hash_alg, config.sig_alg, True, "", True, True #allow deprecated, include cert signer
        )
        return smime_msg_signed
        
    else:
        #error, no config.signer_cert and config.signer_key
        raise ValueError("signer cert AND signer key reqired")
        return ""	


# ----------------------------------
# SMTP sending via SSL or STARTTLS
# ----------------------------------

def send_smtp_ssl(
        smtp_conf: SMTPConfig,
        from_addr: str,
        to_addrs: Sequence[str],
        message_bytes: bytes,
) -> None:
    """
    Send raw RFC822 message over SMTP using SSL (port 465) and username/password.
    """
    if smtp_conf.use_ssl:
        server = smtplib.SMTP_SSL(
            host=smtp_conf.host,
            port=smtp_conf.port,
            timeout=smtp_conf.timeout,
        )
    elif smtp_conf.use_starttls:
        server = smtplib.SMTP(
            host=smtp_conf.host,
            port=smtp_conf.port,
            timeout=smtp_conf.timeout,
        )
    
    else:
        server = smtplib.SMTP(
            host=smtp_conf.host,
            port=smtp_conf.port,
            timeout=smtp_conf.timeout,
        )

    try:
        server.ehlo()
        if smtp_conf.use_starttls:
            server.starttls()
	    
        if smtp_conf.username and smtp_conf.password:
            server.login(smtp_conf.username, smtp_conf.password)  # LOGIN auth
        server.sendmail(from_addr, list(to_addrs), message_bytes)
    finally:
        try:
            server.quit()
        except Exception:
            # Avoid raising on quit
            pass


# ----------------------------
# High-level Functions
# ----------------------------

##message Type1
#send smime mail with open part
def send_mixed_smime_email(
        smtp_conf: SMTPConfig,
        smime_conf: SMimeConfig,
        subject: str,
        from_addr: str,
        to_addrs: Sequence[str],
        secret_text: str,
        open_text: Optional[str] = None,
        open_attachments: Optional[Sequence[Tuple[str, bool]]] = None,
        secret_attachments: Optional[Sequence[Tuple[str, bool]]] = None,
) -> None:

    # Inner secret part to be S/MIME protected
    inner_secret = build_mime(
        subject=subject,
        from_addr=from_addr,
        to_addrs=to_addrs,
        text=secret_text,
        attachments=secret_attachments,
    )

    # S/MIME protect inner part - sign and encrypt
    smime_part = smime_protect(inner_secret, smime_conf)

    #debug write out smime message as file
    if FILE_DUMP: 
        with open("Type1_mixed_mail_signed_encrypted_smime_part.txt", "w", encoding="utf-8") as f:
            f.write(smime_part.as_string())



    # Outer message with non-encrypted content
    outer_msg = build_mime(
        subject=subject,
        from_addr=from_addr,
        to_addrs=to_addrs,
        text=open_text,
        attachments=open_attachments,
    )

    #debug write out outer message as file
    if FILE_DUMP: 
        with open("Type1_mixed_mail_open_message_part.txt", "w", encoding="utf-8") as f:
            f.write(outer_msg.as_string())


    # Attach S/MIME part (application/pkcs7-mime)
    outer_msg.attach(smime_part)
    
    #debug write out smime message as file
    if FILE_DUMP: 
        with open("Type1_complete_smime_of_mixed_signed_and_encrypted_smime.txt", "w", encoding="utf-8") as f:
            f.write(outer_msg.as_string())

    print("message size:", len(outer_msg.as_string()))
    # Send message as bytes
    send_smtp_ssl(
        smtp_conf=smtp_conf,
        from_addr=from_addr,
        to_addrs=to_addrs,
        message_bytes=outer_msg.as_bytes(),
    )

##message Type2
#send signed and encrypted smime_mail
def send_pure_smime_email(
        smtp_conf: SMTPConfig,
        smime_conf: SMimeConfig,
        subject: str,
        from_addr: str,
        to_addrs: Sequence[str],
        secret_text: str,
        secret_attachments: Optional[Sequence[Tuple[str, bool]]] = None,
) -> None:

    # secret to be S/MIME protected
    secret = build_mime(
        subject=subject,
        from_addr=from_addr,
        to_addrs=to_addrs,
        text=secret_text,
        attachments=secret_attachments,
    )

    # S/MIME protect inner part
    smime_part = smime_protect(secret, smime_conf)

    #debug write out smime message as file
    if FILE_DUMP: 
        with open("Type2_complete_smime_of_pure_signed_and_encrypted_smime.txt", "w", encoding="utf-8") as f:
            f.write(smime_part.as_string())

    print("message size:", len(smime_part.as_string()))
    
    send_smtp_ssl(
        smtp_conf=smtp_conf,
        from_addr=from_addr,
        to_addrs=to_addrs,
        message_bytes=smime_part.as_bytes(),
	
    )

##message Type3 (single), Type 4 (multiple)
def send_multiple_encrypted_smime_email(
        smtp_conf: SMTPConfig,
        smime_conf: SMimeConfig,
        subject: str,
        from_addr: str,
        to_addrs: Sequence[str],
        secret_text: str,
        secret_attachments: Optional[Sequence[Tuple[str, bool]]] = None,
        count: int = 1,
) -> None:

    if count == 0:
        return  # Terminate because no encryptions left to be done
    else:

            # secret part to be S/MIME protected
            secret = build_mime(
            subject=subject,
            from_addr=from_addr,
            to_addrs=to_addrs,
            text=secret_text,
            attachments=secret_attachments,
            )

            #debug write out mime message as file
            if FILE_DUMP:
                if count == 1:
                    secret_dump_filename = f"Type3_secret_of_single_encrypted_smime.txt"
                else: 
                    secret_dump_filename = f"Type4_secret_of_multiple_encrypted_smime.txt"
                with open(secret_dump_filename, "w", encoding="utf-8") as f:
                        f.write(secret.as_string())
    

            # Load recipient certs
            recipient_certs_data: List[bytes] = []
            for cert_path in smime_conf.recipient_certs:
                with open(cert_path, "rb") as f:
                    recipient_certs_data.append(f.read())

         

            if SHOW_PROGRESS: print("\nrounds size")
            #multiple rounds of encryption
            for i in range(count, 0, -1):
               
                #encrypt only
                secret_encrypted = encrypt_message(secret, recipient_certs_data, smime_conf.cipher, "rsaes_pkcs1v15", "")
                message_size = len(secret_encrypted.as_string())
	            #next round
                secret = secret_encrypted
                if SHOW_PROGRESS: print(i, message_size) # print step
                if FILE_DUMP:
                    if count == 1:
                        secret_dump_filename = f"Type3_secret_of_single_encrypted_smime_round1.txt"
                    else: 
                        secret_dump_filename = f"Type4_secret_of_multiple{i}_encrypted_smime.txt"
                    with open(secret_dump_filename, "w", encoding="utf-8") as f:
                        f.write(secret.as_string())


            smime_part = secret_encrypted


            #debug write out smime message as file
            if FILE_DUMP: 
                if count == 1:
                    secret_dump_filename = f"Type3_complete_smime_of_single_encrypted_smime.txt"
                else: 
                    secret_dump_filename = f"Type4_complete_smime_of_multiple_encrypted_smime.txt"
                with open(secret_dump_filename, "w", encoding="utf-8") as f:
                    f.write(secret.as_string())
    
            print("message size:", len(smime_part.as_string()))
            send_smtp_ssl(
            smtp_conf=smtp_conf,
            from_addr=from_addr,
            to_addrs=to_addrs,
            message_bytes=smime_part.as_bytes(),
    )
    

##message Type5 (single), Type 6 (multiple)
def send_multiple_signed_smime_email(
        smtp_conf: SMTPConfig,
        smime_conf: SMimeConfig,
        subject: str,
        from_addr: str,
        to_addrs: Sequence[str],
        secret_text: str,
        secret_attachments: Optional[Sequence[Tuple[str, bool]]] = None,
        count: int = 1,
) -> None:

    if count == 0:
        return  # Terminate because no encryptions left to be done
    else:

            # secret part to be S/MIME protected
            secret = build_mime(
            subject=subject,
            from_addr=from_addr,
            to_addrs=to_addrs,
            text=secret_text,
            attachments=secret_attachments,
            )

            #debug write out mime message as file
            if FILE_DUMP:
                if count == 1:
                    secret_dump_filename = f"Type5_secret_of_single_signed_smime.txt"
                else: 
                    secret_dump_filename = f"Type6_secret_of_multiple_signed_smime.txt"
                with open(secret_dump_filename, "w", encoding="utf-8") as f:
                        f.write(secret.as_string())
    


            # Load recipient certs
            recipient_certs_data: List[bytes] = []
            for cert_path in smime_conf.recipient_certs:
                with open(cert_path, "rb") as f:
                    recipient_certs_data.append(f.read())

         

            if SHOW_PROGRESS: print("\nrounds size")
            #multiple rounds of signature
            for i in range(count, 0, -1):
               
                #sign only
                secret_encrypted = sign_message(secret, smime_conf.signer_key, smime_conf.signer_cert, 
                             smime_conf.hash_alg, smime_conf.sig_alg,
                             True, "", True, True)  #allow deprecated, include cert signer
                
                message_size = len(secret_encrypted.as_string())
		#next round
                secret = secret_encrypted
                if SHOW_PROGRESS: print(i, message_size) # print step
                if FILE_DUMP:
                    if count == 1:
                        secret_dump_filename = f"Type5_secret_of_single_signed_smime_round1.txt"
                    else: 
                        secret_dump_filename = f"Type6_secret_of_multiple{i}_signed_smime.txt"
                    with open(secret_dump_filename, "w", encoding="utf-8") as f:
                        f.write(secret.as_string())
			

            smime_part = secret_encrypted


            #debug write out smime message as file
            if FILE_DUMP: 
                if count == 1:
                    secret_dump_filename = f"Type5_complete_smime_of_single_signed_smime.txt"
                else: 
                    secret_dump_filename = f"Type6_complete_smime_of_multiple_signed_smime.txt"
                with open(secret_dump_filename, "w", encoding="utf-8") as f:
                    f.write(secret.as_string())
                 
            print("message size:", len(smime_part.as_string()))

            send_smtp_ssl(
            smtp_conf=smtp_conf,
            from_addr=from_addr,
            to_addrs=to_addrs,
            message_bytes=smime_part.as_bytes(),
    )


##message Type7 (single), Type 8 (multiple)
def send_multiple_signed_encrypted_smime_email(
        smtp_conf: SMTPConfig,
        smime_conf: SMimeConfig,
        subject: str,
        from_addr: str,
        to_addrs: Sequence[str],
        secret_text: str,
        secret_attachments: Optional[Sequence[Tuple[str, bool]]] = None,
        count: int = 1,
) -> None:

    if count == 0:
        return  # Terminate because no encryptions left to be done
    else:

            # secret part to be S/MIME protected
            secret = build_mime(
            subject=subject,
            from_addr=from_addr,
            to_addrs=to_addrs,
            text=secret_text,
            attachments=secret_attachments,
            )

            #debug write out mime message as file
            if FILE_DUMP:

                if count == 1:
                    secret_dump_filename = f"Type7_secret_of_single_signed_and_encrypted_smime.txt"
                else: 
                    secret_dump_filename = f"Type8_secret_of_multiple_signed_and_encrypted_smime.txt"
                with open(secret_dump_filename, "w", encoding="utf-8") as f:
                        f.write(secret.as_string())
    

            # Load recipient certs
            recipient_certs_data: List[bytes] = []
            for cert_path in smime_conf.recipient_certs:
                with open(cert_path, "rb") as f:
                    recipient_certs_data.append(f.read())

         

            if SHOW_PROGRESS: print("\nrounds size")
            #multiple rounds of encryption
            for i in range(count, 0, -1):
               
                #sign and encrypt
                #secret_encrypted = smime_protect(secret, smime_conf)
                secret_encrypted = sign_and_encrypt_message(secret, smime_conf.signer_key, smime_conf.signer_cert, 
		             smime_conf.recipient_certs, 
                             smime_conf.hash_alg, smime_conf.sig_alg,
                             True, "",
                             smime_conf.cipher, "rsaes_pkcs1v15") #key_enc_alg is fixed for now
                
                message_size = len(secret_encrypted.as_string())
		#next round
                secret = secret_encrypted
                if SHOW_PROGRESS: print(i, message_size) # print step
                if FILE_DUMP:
                    if count == 1:
                        secret_dump_filename = f"Type7_secret_of_single_signed_and_encrypted_smime_round1.txt"
                    else: 
                        secret_dump_filename = f"Type8_secret_of_multiple{i}_signed_and_encrypted_smime.txt"
                    with open(secret_dump_filename, "w", encoding="utf-8") as f:
                        f.write(secret.as_string())
			


            smime_part = secret_encrypted


            #debug write out smime message as file
            if FILE_DUMP: 
                if count == 1:
                    secret_dump_filename = f"Type7_complete_smime_of_single_signed_and_encrypted.txt"
                else: 
                    secret_dump_filename = f"Type8_complete_smime_of_multiple_signed_and_encrypted.txt"
                with open(secret_dump_filename, "w", encoding="utf-8") as f:
                        f.write(secret.as_string())
            
            print("message size:", len(smime_part.as_string()))
	    
            send_smtp_ssl(
            smtp_conf=smtp_conf,
            from_addr=from_addr,
            to_addrs=to_addrs,
            message_bytes=smime_part.as_bytes(),
    )


##message Type9 (single), Type 10 (multiple)
#send (multiple) triple wrapped smime mail according to RFC2634 section 1.1
def send_multiple_triple_wrapped_pure_smime_email(
        smtp_conf: SMTPConfig,
        smime_conf: SMimeConfig,
        subject: str,
        from_addr: str,
        to_addrs: Sequence[str],
        secret_text: str,
        secret_attachments: Optional[Sequence[Tuple[str, bool]]] = None,
        count: int = 1,
) -> None:

    if count == 0:
        return  # Terminate because no encryptions left to be done
    else:

            # secret part to be S/MIME protected
            secret = build_mime(
            subject=subject,
            from_addr=from_addr,
            to_addrs=to_addrs,
            text=secret_text,
            attachments=secret_attachments,
            )

            #debug write out mime message as file
            if FILE_DUMP:

                if count == 1:
                    secret_dump_filename = f"Type9_secret_of_single_triple_wrapped_smime.txt"
                else: 
                    secret_dump_filename = f"Type10_secret_of_multiple_triple_wrapped_smime.txt"
                with open(secret_dump_filename, "w", encoding="utf-8") as f:
                        f.write(secret.as_string())


            # Load recipient certs
            recipient_certs_data: List[bytes] = []
            for cert_path in smime_conf.recipient_certs:
                with open(cert_path, "rb") as f:
                    recipient_certs_data.append(f.read())

         

            if SHOW_PROGRESS: print("\nrounds size")
            #multiple rounds of encryption
            for i in range(count, 0, -1):
               
                #sign and encrypt and sign again
                secret_encrypted = smime_protect_and_sign_again(secret, smime_conf)
                
                message_size = len(secret_encrypted.as_string())
		#next round
                secret = secret_encrypted
                if SHOW_PROGRESS: print(i, message_size) # print step
                if FILE_DUMP:

                    if count == 1:
                        secret_dump_filename = f"Type9_secret_of_single_triple_wrapped_smime_round1.txt"
                    else: 
                        secret_dump_filename = f"Type10_secret_of_multiple{i}_triple_wrapped_smime.txt"
                    with open(secret_dump_filename, "w", encoding="utf-8") as f:
                        f.write(secret.as_string())


            smime_part = secret_encrypted


            #debug write out smime message as file
            if FILE_DUMP: 
                if count == 1:
                    secret_dump_filename = f"Type9_complete_smime_of_single_triple_wrapped.txt"
                else: 
                    secret_dump_filename = f"Type10_complete_smime_of_multiple_triple_wrapped.txt"
                with open(secret_dump_filename, "w", encoding="utf-8") as f:
                        f.write(secret.as_string())


            print("message size:", message_size)

            send_smtp_ssl(
            smtp_conf=smtp_conf,
            from_addr=from_addr,
            to_addrs=to_addrs,
            message_bytes=smime_part.as_bytes(),
    )

##message Type11 equals Type 9
#send triple wrapped smime mail according to RFC2634 section 1.1
def send_triple_wrapped_pure_smime_email(
        smtp_conf: SMTPConfig,
        smime_conf: SMimeConfig,
        subject: str,
        from_addr: str,
        to_addrs: Sequence[str],
        secret_text: str,
        secret_attachments: Optional[Sequence[Tuple[str, bool]]] = None,
) -> None:

    # secret to be S/MIME protected
    secret = build_mime(
        subject=subject,
        from_addr=from_addr,
        to_addrs=to_addrs,
        text=secret_text,
        attachments=secret_attachments,
    )

    # S/MIME protect inner part and sign again
    smime_part = smime_protect_and_sign_again(secret, smime_conf)

    #debug write out smime message as file
    if FILE_DUMP:  
        with open("Type11_complete_smime_of_pure_triple_wrapped_smime.txt", "w", encoding="utf-8") as f:
            f.write(smime_part.as_string())

    print("message size:", len(smime_part.as_string()))
	    
    
    send_smtp_ssl(
        smtp_conf=smtp_conf,
        from_addr=from_addr,
        to_addrs=to_addrs,
        message_bytes=smime_part.as_bytes(),


    )


# ----------------------------
# Main
# ----------------------------

def main() -> None:
    print("\n  S/MIME tester") 
    print("-----------------")
    
    #load config from ini file
    smtp_cfg, smime_cfg, from_addr, to_addrs = load_config()
    
    print("\n> loading config from:",CONFIG_PATH)
    print("\n> configuration: \n")
    print("SMTP host:", smtp_cfg.host)
    print("SMTP port:", smtp_cfg.port)
    print("From:", from_addr)
    print("To:", to_addrs)
    print("Use SSL:", smtp_cfg.use_ssl)
    print("Use STARTTLS:", smtp_cfg.use_starttls)
    if smime_cfg:
        print("S/MIME cipher:", smime_cfg.cipher)
        print("S/MIME hash digest algorithm:", smime_cfg.hash_alg)
        print("S/MIME signature algorithm:", smime_cfg.sig_alg)
        print("Signer certificate file:", smime_cfg.signer_cert)
        print("Signer key file:", smime_cfg.signer_key)

        print("\nRecipient cert files:", smime_cfg.recipient_certs)
    print("\n> sending mail\n")

    #--------------
    #compose emails
    #--------------

    # Open (non-encrypted)
    open_body = (
        "This part of the email is not encrypted.\n"
        + "OPEN_BODY\n"
	+ "\nS/MIME CONFIGURATION:\n"
        + "\nS/MIME cipher: " + str(smime_cfg.cipher)
        + "\nS/MIME hash digest algorithm: " + str(smime_cfg.hash_alg)
	+ "\nS/MIME signature algorithm: " + str(smime_cfg.sig_alg)
	+ "\nSigner certificate file: " + str(smime_cfg.signer_cert)
    + "\nRecipient cert files: " + str(smime_cfg.recipient_certs)
    )

    if INCLUDE_ATTACHMENTS:
        open_attachments = [
            ("./attachments/logo.png", True),  # inline logo
            ("./attachments/document.pdf", False),  # regular attachment
        ]
    else:
        open_attachments = []

    # Secret S/MIME-protected content
    secret_body = (
        "This is confidential information. It is protected with S/MIME and "
        "intended only for the listed recipients.\n"
        + "\nSECRET_BODY\n"
	+ "\nS/MIME CONFIGURATION:\n"
        + "\nS/MIME cipher: " + str(smime_cfg.cipher)
        + "\nS/MIME hash digest algorithm: " + str(smime_cfg.hash_alg)
	+ "\nS/MIME signature algorithm: " + str(smime_cfg.sig_alg)
	+ "\nSigner certificate file: " + str(smime_cfg.signer_cert)
    + "\nRecipient cert files: " + str(smime_cfg.recipient_certs)
    )


    if INCLUDE_ATTACHMENTS:
        secret_attachments = [
            ("./attachments/confidential-report.pdf", False),
            ("./attachments/confidential-logo.png", True),
        ]
    else:
        secret_attachments = []


    #-------------------
    #select test emails
    #-------------------

    if MIXED_SMIME_EMAIL:
      print("\nType 1: sending mixed smime email")

      send_mixed_smime_email(
          smtp_conf=smtp_cfg,
          smime_conf=smime_cfg,
          subject="Type 1: Confidential S/MIME message with mixed open content",
          from_addr=from_addr,
          to_addrs=to_addrs,
          secret_text=secret_body,
          open_text=open_body,
          open_attachments=open_attachments,
          secret_attachments=secret_attachments,
      )


    if PURE_SMIME:
      print("\nType 2: sending pure smime email")
      send_pure_smime_email(
           smtp_conf=smtp_cfg,
           smime_conf=smime_cfg,
           subject="Type 2: Pure S/MIME message with content",
           from_addr=from_addr,
           to_addrs=to_addrs,
           secret_text=secret_body,
           secret_attachments=secret_attachments,
       )

       
    if TRIPLE_WRAPPED_PURE_SMIME:
      print("\nType11: sending triple wrapped smime email")
      send_triple_wrapped_pure_smime_email(
           smtp_conf=smtp_cfg,
           smime_conf=smime_cfg,
           subject="Type 11: triple wrapped S/MIME message with content",
           from_addr=from_addr,
           to_addrs=to_addrs,
           secret_text=secret_body,
           secret_attachments=secret_attachments,
       )       
       
       
    if MULTIPLE_TRIPLE_WRAPPED_SMIME:
      rounds_for_encryption = MULTIPLE_TRIPLE_WRAPPED_ROUNDS  
      #problem: email gets bigger with every iteration ...
      print("\nType 10: sending multiple triple wrapped pure smime email. Rounds: ",rounds_for_encryption)
      subject_str = f"Type 10: {rounds_for_encryption} times triple wrapped S/MIME message with content"
      
      send_multiple_triple_wrapped_pure_smime_email(
           smtp_conf=smtp_cfg,
           smime_conf=smime_cfg,
           subject=subject_str,
           from_addr=from_addr,
           to_addrs=to_addrs,
           secret_text=secret_body,
           secret_attachments=secret_attachments,
	       count=rounds_for_encryption,
     )

    if SINGLE_TRIPLE_WRAPPED_SMIME:
      #problem: email gets bigger with every iteration ...
      print("\nType 9: sending single triple wrapped pure smime email. Rounds: ",rounds_for_encryption)
      subject_str = f"Type 9: single times triple wrapped S/MIME message with content"
      
      send_multiple_triple_wrapped_pure_smime_email(
           smtp_conf=smtp_cfg,
           smime_conf=smime_cfg,
           subject=subject_str,
           from_addr=from_addr,
           to_addrs=to_addrs,
           secret_text=secret_body,
           secret_attachments=secret_attachments,
	       count=1,
     )
        
    if MULTIPLE_ENCRYPTED_SMIME:
      rounds_for_encryption = MULTIPLE_CRYPT_ROUNDS 
      #problem: email gets bigger with every iteration ...
      print("\nType 4: sending multiple encrypted pure smime email. Rounds: ",rounds_for_encryption)
      subject_str = f"Type 4: {rounds_for_encryption} times encrypted S/MIME message with content"
      
      send_multiple_encrypted_smime_email(
           smtp_conf=smtp_cfg,
           smime_conf=smime_cfg,
           subject=subject_str,
           from_addr=from_addr,
           to_addrs=to_addrs,
           secret_text=secret_body,
           secret_attachments=secret_attachments,
	       count=rounds_for_encryption,
     )
     
     
    if SINGLE_ENCRYPTED_SMIME: 
      #problem: email gets bigger with every iteration ...
      print("\nType 3: sending single encrypted pure smime email.")
      subject_str = "Type 3: encrypted S/MIME message with content"
      
      send_multiple_encrypted_smime_email(
           smtp_conf=smtp_cfg,
           smime_conf=smime_cfg,
           subject=subject_str,
           from_addr=from_addr,
           to_addrs=to_addrs,
           secret_text=secret_body,
           secret_attachments=secret_attachments,
	       count=1,
     )
     
      
    if MULTIPLE_SIGNED_SMIME:
      rounds_for_encryption = MULTIPLE_SIGN_ROUNDS  
      #problem: email gets bigger with every iteration ...
      print("\nType 6: sending multiple signed pure smime email. Rounds: ",rounds_for_encryption)
      subject_str = f"Type 6: {rounds_for_encryption} times signed S/MIME message with content"
      
      send_multiple_signed_smime_email(
           smtp_conf=smtp_cfg,
           smime_conf=smime_cfg,
           subject=subject_str,
           from_addr=from_addr,
           to_addrs=to_addrs,
           secret_text=secret_body,
           secret_attachments=secret_attachments,
	       count=rounds_for_encryption,
     )


    if SINGLE_SIGNED_SMIME:
      print("\nType 5: sending single signed pure smime email.")
      subject_str = "Type 5: signed S/MIME message with content"
      
      send_multiple_signed_smime_email(
           smtp_conf=smtp_cfg,
           smime_conf=smime_cfg,
           subject=subject_str,
           from_addr=from_addr,
           to_addrs=to_addrs,
           secret_text=secret_body,
           secret_attachments=secret_attachments,
	       count=1,
     )


    if MULTIPLE_SIGNED_ENCRYPTED_SMIME:
      rounds_for_encryption = MULTIPLE_SIGN_CRYPT_ROUNDS  
      #problem: email gets bigger with every iteration ...
      print("\nType 8: sending multiple signed and encrypted pure smime email. Rounds: ",rounds_for_encryption)
      subject_str = f"Type 8: {rounds_for_encryption} times signed and encrypted S/MIME message with content"
      
      send_multiple_signed_encrypted_smime_email(
           smtp_conf=smtp_cfg,
           smime_conf=smime_cfg,
           subject=subject_str,
           from_addr=from_addr,
           to_addrs=to_addrs,
           secret_text=secret_body,
           secret_attachments=secret_attachments,
	       count=rounds_for_encryption,
     )


    if SINGLE_SIGNED_ENCRYPTED_SMIME:
      rounds_for_encryption = MULTIPLE_SIGN_CRYPT_ROUNDS  
      print("\nType 7: sending single signed and encrypted pure smime email.")
      subject_str = "Type 7: single signed and encrypted S/MIME message with content"
      
      send_multiple_signed_encrypted_smime_email(
           smtp_conf=smtp_cfg,
           smime_conf=smime_cfg,
           subject=subject_str,
           from_addr=from_addr,
           to_addrs=to_addrs,
           secret_text=secret_body,
           secret_attachments=secret_attachments,
	       count=1,
     )


if __name__ == "__main__":
    main()

#WARNING CREDENTIALS IN config.ini!
