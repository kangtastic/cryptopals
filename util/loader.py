# -*- coding: utf-8 -*-
import base64
import os


def loader(file, decoder, split=True):
    file_dir = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
    cdata_path = os.path.join(os.path.split(file_dir)[0], "static", file)

    if decoder == "hexstring":
        decoder = bytes.fromhex
    elif decoder == "base64":
        decoder = base64.b64decode

    with open(cdata_path) as f:
        if split:
            return list(map(decoder, f))
        else:
            return decoder(f.read())
