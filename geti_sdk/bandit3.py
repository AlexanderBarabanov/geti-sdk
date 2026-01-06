"""
More intentionally insecure code for Bandit HIGH severity testing.
DO NOT USE IN REAL APPLICATIONS.
"""

import os
import subprocess
import ssl
import socket
import ftplib
import telnetlib
import xml.etree.ElementTree as ET
import hashlib
import base64


def hardcoded_password():
    """
    Bandit: B105 - hardcoded password (HIGH)
    """
    password = "P@ssw0rd123"
    return password


def hardcoded_private_key():
    """
    Bandit: B106 - hardcoded private key (HIGH)
    """
    private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALfakekeycontenthereIDAQAB
-----END RSA PRIVATE KEY-----"""
    return private_key


def weak_crypto_md5(data):
    """
    Bandit: B303 - weak cryptographic hash (HIGH)
    """
    return hashlib.md5(data).hexdigest()


def weak_crypto_sha1(data):
    """
    Bandit: B303 - weak cryptographic hash (HIGH)
    """
    return hashlib.sha1(data).hexdigest()


def insecure_ssl_context():
    """
    Bandit: B502 - SSL with CERT_NONE (HIGH)
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def insecure_socket_connection():
    """
    Bandit: B507 - SSL context without certificate validation (HIGH)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    wrapped = ssl.wrap_socket(sock, cert_reqs=ssl.CERT_NONE)
    return wrapped


def insecure_ftp_login():
    """
    Bandit: B401 - FTP used (cleartext credentials) (HIGH)
    """
    ftp = ftplib.FTP("example.com")
    ftp.login("admin", "admin123")
    return ftp


def insecure_telnet_usage():
    """
    Bandit: B401 - Telnet used (HIGH)
    """
    tn = telnetlib.Telnet("example.com")
    tn.write(b"admin\n")
    tn.write(b"password\n")
    return tn


def insecure_xml_parsing(xml_data):
    """
    Bandit: B405/B406 - XML external entity attack (XXE) (HIGH)
    """
    return ET.fromstring(xml_data)


def insecure_base64_secrets():
    """
    Bandit: B102 - hardcoded secret (HIGH)
    """
    secret = base64.b64encode(b"super_secret_key")
    return secret


def command_injection_check_output(user_input):
    """
    Bandit: B603 - subprocess call with untrusted input (HIGH)
    """
    return subprocess.check_output(
        "cat " + user_input,
        shell=True
    )


if __name__ == "__main__":
    weak_crypto_md5(b"test")
    weak_crypto_sha1(b"test")
    insecure_ssl_context()
    insecure_socket_connection()
    insecure_ftp_login()
    insecure_telnet_usage()
    insecure_xml_parsing("<root></root>")
    command_injection_check_output("; echo hacked")
