#!/usr/bin/python3.6

import os
import sys
import xml
import zlib
import base64
import zipfile
import subprocess
from os import DirEntry, path
from shutil import rmtree
from typing import Optional
from xml.sax import ContentHandler
from xml.sax.xmlreader import AttributesImpl

from Crypto.Cipher import AES

#
# Decrypts LibreOffice messed up by half-assed GPG2Libre implementation, namely GPG encryption.
#
# Usage: ./libreFromGPG.py [filename]
#
# Uses pycryptodome or pycrypto. Requires gpg and your secret key added to it.
#
# -- cab404

encrypted_odt_name = sys.argv[1]
assembly_location = ".tmp_repair_odf"
print(
    f"Will be decrypting {encrypted_odt_name}, using {path.join(path.abspath(path.curdir), assembly_location)} as temp folder.")


def terminate(code):
    rmtree(assembly_location)
    exit(code)

def decrypt_odf_file(text: bytes, passphrase: bytes, iv: bytes, hash: str, logname="") -> Optional[bytes]:
    """
    :param text: encrypted text
    :param passphrase: decrypted cipher section
    :param hash: sha256 hash to verify decrypted text against
    :param iv: iv of encryption key of this file
    :param logname: log tag
    :return: decrypted text
    """

    cipher = AES.new(passphrase, AES.MODE_CBC, iv)

    dec = cipher.decrypt(text)

    # SHA256_1K
    # dec_hash = base64.b64encode(SHA256.new(dec[:1024]).digest()).decode()

    # print(f"{logname}: decrypted text hash {dec_hash}")
    # print(f"{logname}: verification hash   {hash}")
    # if hash != dec_hash:

    return zlib.decompress(dec, wbits=-15)


def decrypt_cipher(enc_cipher: str):
    raw_cipher = base64.b64decode(enc_cipher.strip())
    result = subprocess.run(["gpg", "--decrypt"], input=raw_cipher, stdout=subprocess.PIPE).stdout
    return result


file = zipfile.ZipFile(encrypted_odt_name, mode="r")

try:
    os.mkdir(assembly_location)
except FileExistsError:
    pass

# extracting odt so we can modify files much easier.
file.extractall(assembly_location)

manifest_location = "META-INF/manifest.xml"

new_manifest = open(path.join(assembly_location, manifest_location), "w")
new_manifest.write("""<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2">\n""")

# we are parsing manifest.xml for encrypted files, and forming new manifest.xml.
class Handler(ContentHandler):
    last_el_name = ""

    cipher = None
    fname = None
    hash = None
    iv = None

    def startElement(self, name: str, attrs: AttributesImpl):
        self.last_el_name = name
        # means we encountered new file entry. we can write down it's path.
        if name == "manifest:file-entry":
            self.fname = attrs["manifest:full-path"]
            new_manifest.write(
                f"""  <manifest:file-entry manifest:full-path="{self.fname}" manifest:version="1.2" manifest:media-type="{attrs["manifest:media-type"]}"/>\n"""
            )
            if self.cipher is None:
                print("No cipher found, probably not a PGP encrypted file.")
                terminate(1)
        # means we encountered previous file entries checksum.
        if name == "manifest:encryption-data":
            self.hash = attrs["manifest:checksum"]
        # means we encountered previous file entries iv.
        if name == "manifest:algorithm":
            self.iv = base64.b64decode(attrs["manifest:initialisation-vector"].strip())

    def characters(self, content):
        # really important thing.
        if self.last_el_name == "loext:CipherValue":
            self.cipher = decrypt_cipher(content)
            self.last_el_name = None

    def endElement(self, name):
        if name == "manifest:file-entry":
            if self.fname is not None and self.hash is not None and self.iv is not None:
                target = decrypt_odf_file(
                    file.open(self.fname).read(),
                    self.cipher,
                    self.iv,
                    self.hash,
                    logname=self.fname
                )
                with open(assembly_location + "/" + self.fname, "wb") as edited:
                    edited.write(target)
                print(f"[OK]   {self.fname}")

            else:
                print(f"[SKIP] {self.fname}")
            self.fname = self.hash = self.iv = None


xml.sax.parse(file.open(manifest_location), Handler())

new_manifest.write("</manifest:manifest>")
new_manifest.close()

# decrypted file location
dec_odt = zipfile.ZipFile(
    path.join(
        path.dirname(encrypted_odt_name),
        "decrypted_" + path.basename(encrypted_odt_name)
    ),
    "w"
)


def deep_compress(dir):
    with os.scandir(dir) as scanner:
        for entry in scanner:
            entry: DirEntry = entry
            if entry.is_dir():
                deep_compress(path.join(dir, entry.name))
            else:
                print(f"packing back {entry.path}")
                with open(entry.path, "rb") as compressee:
                    writethis = compressee.read()
                    dec_odt.writestr(path.relpath(entry.path, start=assembly_location), writethis)


deep_compress(assembly_location)
dec_odt.close()

print("---")
print(f"success. written decrypted document into {dec_odt.filename}")
terminate(0)
