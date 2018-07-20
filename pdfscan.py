# -*- coding: utf-8 -*-
# This file is part of MaliceIO - https://github.com/malice-plugins/pdf
# See the file 'LICENSE' for copying permission.

__description__ = 'Malice PDF Plugin'
__author__ = 'blacktop - <https://github.com/blacktop>'
__version__ = '0.1.0'
__date__ = '2018/01/29'

import hashlib
import json
import logging
import optparse
import os
import re
import sys
import tempfile
import unicodedata

from elastic import Elastic
from pdfid import pdfid
from pdfparser import pdf_parser

log = logging.getLogger(__name__)


class PDF(object):

    def __init__(self, file_path):
        self.file = file_path
        self.oPDFiD = None
        self.init_logging()

    def init_logging(self):
        # create console handler and set level to debug
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        # add ch to logger
        log.addHandler(ch)

    @staticmethod
    def sha256_checksum(filename, block_size=65536):
        sha256 = hashlib.sha256()
        with open(filename, 'rb') as f:
            for block in iter(lambda: f.read(block_size), b''):
                sha256.update(block)
        return sha256.hexdigest()

    def pdf_id(self):

        #################
        # PDFiD PLUGINS #
        #################
        def nameobfuscation():
            if sum([oCount.hexcode for oCount in self.oPDFiD.keywords.values()]) > 0:
                return dict(score=1.0, reason='hex encoded flag(s) detected')
            else:
                return dict(score=0.0, reason='no hex encoded flags detected')

        def embeddedfile():
            if '/EmbeddedFile' in self.oPDFiD.keywords and self.oPDFiD.keywords['/EmbeddedFile'].count > 0:
                if self.oPDFiD.keywords['/EmbeddedFile'].hexcode > 0:
                    return dict(score=1.0, reason='EmbeddedFile flag(s) are hex encoded')
                else:
                    return dict(score=0.9, reason='EmbeddedFile flag(s) detected')
            else:
                return dict(score=0.0, reason='no EmbeddedFile flag(s) detected')

        def triage():
            for keyword in ('/JS', '/JavaScript', '/AA', '/OpenAction', '/AcroForm', '/JBIG2Decode', '/RichMedia',
                            '/Launch', '/EmbeddedFile', '/XFA', '/Colors > 2^24'):
                if keyword in self.oPDFiD.keywords and self.oPDFiD.keywords[keyword].count > 0:
                    return dict(score=1.0, reason='sample is likely malicious and requires further analysis')
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

        def suspicious():
            return {}

        if not os.path.isfile(self.file):
            raise Exception("{} is not a valid file".format(self.file))

        # run the parser - returns an XML DOM instance
        pdf_data = pdfid.PDFiD(self.file, False, True)
        self.oPDFiD = pdfid.cPDFiD(pdf_data, True)

        # convert to JSON
        pdf_json = pdfid.PDFiD2JSON(pdf_data, True)
        pdf_dict = json.loads(pdf_json)[0]

        heuristics = {
            'nameobfuscation': nameobfuscation(),
            'embeddedfile': embeddedfile(),
            'triage': triage(),
            'suspicious': suspicious()
        }
        pdf_dict['pdfid']['heuristics'] = heuristics

        # clean up JSON
        pdf_dict['pdfid'].pop('filename', None)

        return pdf_dict

    def pdf_parser(self):
        return {}

    def peepdf(self):
        return {}


def main():
    MALICE_PLUGIN_NAME = 'pdf'
    moredesc = '''

Version: v{}, BuildTime: {}

Author:
  {}
'''.format(__version__, __date__, __author__)

    oParser = optparse.OptionParser(
        usage='Usage: malice/pdf [OPTIONS] COMMAND [arg...]\n\n' + __description__ + moredesc,
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
        oParser.print_help()
        sys.exit(1)
    else:
        try:
            pdf = PDF(args[0])

            pdf_dict = {}
            pdf_dict[MALICE_PLUGIN_NAME] = pdf.pdf_id()
            pdf_dict[MALICE_PLUGIN_NAME]['streams'] = pdf.pdf_parser()
            pdf_dict[MALICE_PLUGIN_NAME]['peepdf'] = pdf.peepdf()

            malice_json = {'plugins': {'doc': pdf_dict}}

            # write to elasticsearch
            e = Elastic("127.0.0.1")
            e.write(id=pdf.sha256_checksum(pdf.file), doc=malice_json)

            print json.dumps(malice_json)

        except Exception as e:
            log.exception("failed to run malice plugin: {}".format(MALICE_PLUGIN_NAME))
            return


if __name__ == '__main__':
    main()
