# -*- coding: utf-8 -*-
# This file is part of MaliceIO - https://github.com/malice-plugins/pdf
# See the file 'LICENSE' for copying permission.

import hashlib


def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()


def sha512_checksum(filename, block_size=65536):
    sha512 = hashlib.sha512()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha512.update(block)
    return sha512.hexdigest()