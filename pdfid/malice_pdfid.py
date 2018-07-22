# -*- coding: utf-8 -*-
# This file is part of MaliceIO - https://github.com/malice-plugins/pdf
# See the file 'LICENSE' for copying permission.

__description__ = 'Malice PDF Plugin - PDFiD helper util'
__author__ = 'blacktop - <https://github.com/blacktop>'
__version__ = '0.1.0'
__date__ = '2018/07/21'

import json
from os import path

from utils import sha256_checksum

from . import pdfid


class MalPDFiD(object):

    def __init__(self, file_path):
        self.file = file_path
        self.sha256 = sha256_checksum(self.file)
        self.oPDFiD = None

    #################
    # PDFiD PLUGINS #
    #################
    def nameobfuscation(self):
        if sum([oCount.hexcode for oCount in self.oPDFiD.keywords.values()]) > 0:
            return dict(score=1.0, reason='hex encoded flag(s) detected')
        else:
            return dict(score=0.0, reason='no hex encoded flags detected')

    def embeddedfile(self):
        if '/EmbeddedFile' in self.oPDFiD.keywords and self.oPDFiD.keywords['/EmbeddedFile'].count > 0:
            if self.oPDFiD.keywords['/EmbeddedFile'].hexcode > 0:
                return dict(score=1.0, reason='`/EmbeddedFile` flag(s) are hex encoded')
            else:
                return dict(score=0.9, reason='`/EmbeddedFile` flag(s) detected')
        else:
            return dict(score=0.0, reason='no `/EmbeddedFile` flag(s) detected')

    def triage(self):
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
                        score=0.6, reason='sample is likely not malicious but could contain phishing or payload URL')
            if self.oPDFiD.keywords['obj'].count != self.oPDFiD.keywords['endobj'].count:
                return dict(score=0.5, reason='sample is likely not malicious but requires further analysis')
            if self.oPDFiD.keywords['stream'].count != self.oPDFiD.keywords['endstream'].count:
                return dict(score=0.5, reason='sample is likely not malicious but requires further analysis')
        return dict(score=0.0, reason='sample is likely not malicious')

    def suspicious(self):
        total = 0
        results = {'total': 0, 'reasons': []}
        # Entropy. Typically data outside of streams contain dictionaries & pdf entities (mostly all ASCII text).
        if self.oPDFiD.non_stream_entropy > 6:
            total += 500
            results['reasons'] = dict(score=500, reason='Outside stream entropy of > 5')
        # Pages. Many malicious PDFs will contain only one page.
        if '/Page' in self.oPDFiD.keywords and self.oPDFiD.keywords['/Page'].count == 1:
            total += 50
            results['reasons'] = dict(score=50, reason='Page count of 1')
        # Characters after last %%EOF.
        if self.oPDFiD.last_eof_bytes > 100:
            if self.oPDFiD.last_eof_bytes > 499:
                total += 500
                results['reasons'] = dict(score=500, reason='Over 500 characters after last %%EOF')
            else:
                total += 100
                results['reasons'] = dict(score=100, reason='Over 100 characters after last %%EOF')
        if self.oPDFiD.keywords['obj'].count != self.oPDFiD.keywords['endobj'].count:
            total += 50
            results['reasons'] = dict(score=50, reason='obj" keyword count does not equal "endobj" keyword count')
        if self.oPDFiD.keywords['stream'].count != self.oPDFiD.keywords['endstream'].count:
            total += 50
            results['reasons'] = dict(score=50, reason='Sample "stream" keyword count does not equal "endstream" count')

        results['total'] = total

        return results

    def run(self):

        if not path.isfile(self.file):
            raise Exception("{} is not a valid file".format(self.file))

        # run the parser - returns an XML DOM instance
        pdf_data = pdfid.PDFiD(self.file, False, True)
        try:
            self.oPDFiD = pdfid.cPDFiD(pdf_data, force=True)
        except IndexError:
            if not pdf_data.documentElement.getAttribute('IsPDF') == 'True':
                return dict(error='file cannot be analyzed by PDFiD because it is not a PDF')

        # convert to JSON
        pdf_json = pdfid.PDFiD2JSON(pdf_data, True)
        pdf_dict = json.loads(pdf_json)[0]

        # gather PDF heuristics
        heuristics = {
            'nameobfuscation': self.nameobfuscation(),
            'embeddedfile': self.embeddedfile(),
            'triage': self.triage(),
            'suspicious': self.suspicious()
        }
        pdf_dict['pdfid']['heuristics'] = heuristics

        # clean up JSON
        pdf_dict['pdfid'].pop('filename', None)

        return pdf_dict['pdfid']
