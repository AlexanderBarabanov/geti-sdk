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


def insecure_xml_parsing(xml_data):
    """
    Bandit: B405/B406 - XML external entity attack (XXE) (HIGH)
    """
    return ET.fromstring(xml_data)


if __name__ == "__main__":
    insecure_xml_parsing("<root></root>")
