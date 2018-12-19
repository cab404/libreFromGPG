libreFromGPG
---

Decrypts LibreOffice files messed up by half-assed GPG2Libre implementation of GPG encryption.

Like, that is exactly one half, it encrypts perfectly and it doesn't decrypt at all.

Usage: `./libreFromGPG.py [filename]`

Uses pycryptodome or pycrypto. Requires gpg and your secret key added to it.
