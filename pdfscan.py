# -*- coding: utf-8 -*-
# This file is part of MaliceIO - https://github.com/malice-plugins/pdf
# See the file 'LICENSE' for copying permission.

__description__ = 'Malice PDF Plugin'
__author__ = 'blacktop - <https://github.com/blacktop>'
__version__ = '0.1.0'
__date__ = '2018/01/29'

import json
import logging
import os
import re
import tempfile
import unicodedata

from pdfid import pdfid
from pdfparser import pdf_parser


class PDF(object):

    def __init__(self, file_path):
        self.log = logging.getLogger(__name__)
        self.file = file_path
        init_logging()

    def init_logging(self):
        self.log.setLevel(logging.DEBUG)
        # create console handler and set level to debug
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)

        # create formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        # add formatter to ch
        ch.setFormatter(formatter)

        # add ch to logger
        self.log.addHandler(ch)

    def pdf_id(self):
        def nameobfuscation(self):
            for
        # Run the parser - Returns an XML DOM Instance.
        pdf_data = pdfid.PDFiD(self.file, False, True)

        # This converts to string.
        # pdf_string = PDFiD2String(pdf_data, True)

        # This converts to JSON.
        pdf_json = pdfid.PDFiD2JSON(pdf_data, True)
        print pdf_json[0]
        # Convert from string.
        pdf = json.loads(pdf_json)[0]



def main():
    moredesc = '''

Arguments:
pdf-file and zip-file can be a single file, several files, and/or @file
@file: run PDFiD on each file listed in the text file specified
wildcards are supported

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com'''

    oParser = optparse.OptionParser(
        usage='Usage: malice/pdf [OPTIONS] COMMAND [arg...]\n' + __description__ + moredesc,
        version='%prog ' + __version__)
    oParser.add_option('-c', '--callback', action='store_true', default=False, help='POST results to Malice webhook [$MALICE_ENDPOINT]')
    oParser.add_option(
        '-V', '--verbose', action='store_true', default=False, help='verbose output')
    oParser.add_option('-S', '--select', type=str, default='', help='selection expression')
    oParser.add_option('-o', '--output', type=str, default='', help='output to log file')
    oParser.add_option('--pluginoptions', type=str, default='', help='options for the plugin')
    (options, args) = oParser.parse_args()

    if len(args) == 0:

    else:
        try:
            file_path = ExpandFilenameArguments(args)
        except Exception as e:
            print(e)
            return

    pdf = PDF("test/pdf-doc-vba-eicar-dropper.pdf")
    pdf.pdf_id()


if __name__ == '__main__':
    main()
