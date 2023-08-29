""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import os
from M2Crypto import BIO, SMIME, X509
from tempfile import NamedTemporaryFile
from connectors.cyops_utilities.builtins import download_file_from_cyops, save_file_in_env
from connectors.core.connector import get_logger, ConnectorError
from integrations.crudhub import make_request

logger = get_logger('smime-messaging')

TMP_PATH = '/tmp/'


class SMIMEMessaging(object):
    def __init__(self, config, *args, **kwargs):
        # Instantiate an SMIME object.
        self.smime = SMIME.SMIME()

        if isinstance(config.get('public_key', {}), dict) and config.get('public_key', {}).get('@type') == "File":
            url = config.get('public_key', {}).get('@id')
            public_key = make_request(url, 'GET')
        public_key_file = NamedTemporaryFile(delete=False)
        public_key_file.write(bytes(public_key, 'utf-8'))
        self.public_key_file = public_key_file.name
        public_key_file.close()

        if isinstance(config.get('private_key', {}), dict) and config.get('private_key', {}).get('@type') == "File":
            url = config.get('private_key', {}).get('@id')
            private_key = make_request(url, 'GET')
        private_key_file = NamedTemporaryFile(delete=False)
        private_key_file.write(bytes(private_key, 'utf-8'))
        self.private_key_file = private_key_file.name
        private_key_file.close()

        self.verify_ssl = config.get('verify_ssl')


def makebuf(text):
    return BIO.MemoryBuffer(text)


def sign_email(config, params, *args, **kwargs):
    try:
        client = SMIMEMessaging(config)
        message_body = params.get('body', '')

        # Make a MemoryBuffer of the message.
        buf = makebuf(message_body.encode())

        # Instantiate an SMIME object; set it up; sign the buffer.
        client.smime.load_key(client.private_key_file, client.public_key_file)
        p7 = client.smime.sign(buf, SMIME.PKCS7_DETACHED)

        # Make a MemoryBuffer of the message.
        buf = makebuf(message_body.encode())
        out = BIO.MemoryBuffer()
        client.smime.write(out, p7, buf, SMIME.PKCS7_TEXT)
        signed = out.read().decode('utf-8')
        response = {
            "SMIME.Signed.Email": {
                "message": signed
            }
        }
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def verify_sign(config, params, *args, **kwargs):
    try:
        client = SMIMEMessaging(config)
        # Require File Path
        if params.get('file_iri') and '/api/3/files/' not in params.get('file_iri'):
            file_path = os.path.join(TMP_PATH, params.get('file_iri'))
        else:
            file_iri = params.get('file_iri')
            dw_file_md = download_file_from_cyops(file_iri)
            file_path = TMP_PATH + dw_file_md['cyops_file_path']

        # Load the signer's cert.
        x509 = X509.load_cert(client.public_key_file)
        sk = X509.X509_Stack()
        sk.push(x509)
        client.smime.set_x509_stack(sk)

        # Load the signer's CA cert. In this case, because the signer's
        # cert is self-signed, it is the signer's cert itself.
        st = X509.X509_Store()
        st.load_info(client.public_key_file)
        client.smime.set_x509_store(st)

        # Load the data, verify it.
        p7, data = SMIME.smime_load_pkcs7(file_path)
        v = client.smime.verify(p7, data, flags=SMIME.PKCS7_NOVERIFY)
        if os.path.exists(file_path):
            save_file_in_env(kwargs.get('env', {}), file_path)
        return {"result": "Verified the signature!!!"}
    except Exception as err:
        raise ConnectorError(str(err))


def encrypt_email(config, params, *args, **kwargs):
    try:
        client = SMIMEMessaging(config)
        message_body = params.get('body', '').encode('utf-8')

        # Make a MemoryBuffer of the message.
        buf = makebuf(message_body)

        # Load target cert to encrypt to.
        x509 = X509.load_cert(client.public_key_file)
        sk = X509.X509_Stack()
        sk.push(x509)
        client.smime.set_x509_stack(sk)

        # Set cipher: 3-key triple-DES in CBC mode.
        client.smime.set_cipher(SMIME.Cipher('des_ede3_cbc'))

        # Encrypt the buffer.
        p7 = client.smime.encrypt(buf)

        # Output p7 in mail-friendly format.
        out = BIO.MemoryBuffer()
        client.smime.write(out, p7)
        encrypted_message = out.read().decode('utf-8')
        response = {
            "SMIME.Encrypted.Email": {
                "message": encrypted_message
            }
        }
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def decrypt_email(config, params, *args, **kwargs):
    try:
        client = SMIMEMessaging(config)
        # Require File Path
        if params.get('file_iri') and '/api/3/files/' not in params.get('file_iri'):
            file_path = os.path.join(TMP_PATH, params.get('file_iri'))
        else:
            file_iri = params.get('file_iri')
            dw_file_md = download_file_from_cyops(file_iri)
            file_path = TMP_PATH + dw_file_md['cyops_file_path']

        # Load private key and cert.
        client.smime.load_key(client.private_key_file, client.public_key_file)

        # Load the encrypted data.
        p7, data = SMIME.smime_load_pkcs7(file_path)

        # Decrypt p7.
        decrypted_message = client.smime.decrypt(p7)
        response = {
            "SMIME.Decrypted.Email": {
                "message": decrypted_message
            }
        }
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def check_health(config):
    try:
        client = SMIMEMessaging(config)
        if client.public_key_file and client.private_key_file:
            return True
    except Exception as err:
        raise ConnectorError(str(err))


operations = {
    'sign_email': sign_email,
    'verify_sign': verify_sign,
    'encrypt_email': encrypt_email,
    'decrypt_email': decrypt_email
}
