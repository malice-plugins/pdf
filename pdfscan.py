# -*- coding: utf-8 -*-
# This file is part of MaliceIO - https://github.com/malice-plugins/pdf
# See the file 'LICENSE' for copying permission.

__description__ = 'Malice PDF Plugin'
__author__ = 'blacktop - <https://github.com/blacktop>'
__version__ = '0.1.0'
__date__ = '2018/01/29'

import json
import logging
import optparse
import os
import re
import tempfile
import unicodedata

from pdfid import pdfid
from pdfparser import pdf_parser


class PDF(object):

    def __init__(self, file_path):
        self.oPDFiD = None
        self.log = logging.getLogger(__name__)
        self.file = file_path
        self.init_logging()

    def init_logging(self):
        # create console handler and set level to debug
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        # add ch to logger
        self.log.addHandler(ch)

    def pdf_id(self):

        #################
        # PDFiD PLUGINS #
        #################
        def nameobfuscation():
            if sum([oCount.hexcode for oCount in self.oPDFiD.keywords.values()]) > 0:
                return dict(score=1.0)
            else:
                return dict(score=0.0)

        def embeddedfile():
            if '/EmbeddedFile' in self.oPDFiD.keywords and self.oPDFiD.keywords['/EmbeddedFile'].count > 0:
                if self.oPDFiD.keywords['/EmbeddedFile'].hexcode > 0:
                    return dict(score=1.0)
                else:
                    return dict(score=0.9)
            else:
                return dict(score=0.0)

        def triage():
            for keyword in ('/JS', '/JavaScript', '/AA', '/OpenAction', '/AcroForm', '/JBIG2Decode', '/RichMedia',
                            '/Launch', '/EmbeddedFile', '/XFA', '/Colors > 2^24'):
                if keyword in self.oPDFiD.keywords and self.oPDFiD.keywords[keyword].count > 0:
                    return dict(score=1.0, reason='Sample is likely malicious and requires further analysis')
                for keyword in ('/ObjStm',):
                    if keyword in self.oPDFiD.keywords and self.oPDFiD.keywords[keyword].count > 0:
                        return dict(score=0.75, reason='/ObjStm detected, analyze sample with pdfid-objstm.bat')
                for keyword in ('/URI',):
                    if keyword in self.oPDFiD.keywords and self.oPDFiD.keywords[keyword].count > 0:
                        return dict(
                            score=0.6,
                            reason='sample is likely not malicious but could contain phishing or payload URL')
                if self.oPDFiD.keywords['obj'].count != self.oPDFiD.keywords['endobj'].count:
                    return dict(score=0.5, reason='sample is likely not malicious but requires further analysis')
                if self.oPDFiD.keywords['stream'].count != self.oPDFiD.keywords['endstream'].count:
                    return dict(score=0.5, reason='sample is likely not malicious but requires further analysis')
            return dict(score=0.0, reason='sample is likely not malicious')

        # Run the parser - Returns an XML DOM Instance.
        pdf_data = pdfid.PDFiD(self.file, False, True)

        # This converts to JSON.
        pdf_json = pdfid.PDFiD2JSON(pdf_data, True)
        pdf_dict = json.loads(pdf_json)[0]

        self.oPDFiD = pdfid.cPDFiD(pdf_data, True)
        # print 'Name Obfuscation: {}'.format(nameobfuscation())
        # print 'Embedded File: {}'.format(embeddedfile())
        # print 'Triage: {}'.format(triage())
        plugins = {'nameobfuscation': nameobfuscation(), 'embeddedfile': embeddedfile(), 'triage': triage()}
        pdf_dict['plugins'] = plugins

        print json.dumps(pdf_dict)


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
    oParser.add_option(
        '-c',
        '--callback',
        action='store_true',
        default=False,
        help='POST results to Malice webhook [$MALICE_ENDPOINT]')
    oParser.add_option('-V', '--verbose', action='store_true', default=False, help='verbose output')
    oParser.add_option('-S', '--select', type=str, default='', help='selection expression')
    oParser.add_option('-o', '--output', type=str, default='', help='output to log file')
    oParser.add_option('--pluginoptions', type=str, default='', help='options for the plugin')
    (options, args) = oParser.parse_args()

    if len(args) == 0:
        return
    else:
        try:
            pass
            # file_path = ExpandFilenameArguments(args)
        except Exception as e:
            print(e)
            return

    pdf = PDF("test/pdf-doc-vba-eicar-dropper.pdf")
    pdf.pdf_id()


if __name__ == '__main__':
    main()
