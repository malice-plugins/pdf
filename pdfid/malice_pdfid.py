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
            return dict(score=1000, reason='hex encoded flag(s) detected')
        else:
            return dict(score=0, reason='no hex encoded flags detected')

    def embeddedfile(self):
        if '/EmbeddedFile' in self.oPDFiD.keywords and self.oPDFiD.keywords['/EmbeddedFile'].count > 0:
            if self.oPDFiD.keywords['/EmbeddedFile'].hexcode > 0:
                return dict(score=1000, reason='`/EmbeddedFile` flag(s) are hex encoded')
            else:
                return dict(score=50, reason='`/EmbeddedFile` flag(s) detected')
        else:
            return dict(score=0, reason='no `/EmbeddedFile` flag(s) detected')

    def triage(self):
        score = 0
        results = {'score': 0, 'reasons': []}
        reasons = {
            '/JS':
            '`/JS`: indicating javascript is present in the file.',
            '/JavaScript':
            '`/JavaScript`: indicating javascript is present in the file.',
            '/AA':
            '`/AA`: indicating automatic action to be performed when the page/document is viewed.',
            '/Annot':
            '`/Annot`: sample contains annotations.'
            'Not suspicious but should be examined if other signs of maliciousness present.',
            '/OpenAction':
            '`/OpenAction`: indicating automatic action to be performed when the page/document is viewed.',
            '/AcroForm':
            '`/AcroForm`: sample contains AcroForm object. These can be used to hide malicious code.',
            '/JBIG2Decode':
            '`/JBIG2Decode`: indicating JBIG2 compression.',
            '/RichMedia':
            '`/RichMedia`: indicating embedded Flash.',
            '/Launch':
            '`/Launch`: counts launch actions.',
            '/Encrypt':
            '`/Encrypt`: encrypted content in sample',
            '/XFA':
            '`/XFA`: indicates XML Forms Architecture. These can be used to hide malicious code.',
            '/Colors > 2^24':
            '`/Colors > 2^24`: hits when the number of colors is expressed with more than 3 bytes.',
            '/ObjStm':
            '`/ObjStm`: sample contains object stream(s). Can be used to obfuscate objects.',
            '/URI':
            '`/URI`: sample contains URLs.'
        }

        # Javascript - separated so we do not double-score
        if '/JS' in self.oPDFiD.keywords and self.oPDFiD.keywords['/JS'].count > 0:
            results['reasons'].append(reasons['/JS'])
        if '/JavaScript' in self.oPDFiD.keywords and self.oPDFiD.keywords['/JavaScript'].count > 0:
            results['reasons'].append(reasons['/JavaScript'])
        if self.oPDFiD.keywords['/JavaScript'].count > 0 or self.oPDFiD.keywords['/JS'].count > 0:
            score += 100
        for keyword in ('/JBIG2Decode', '/Colors > 2^24'):
            if keyword in self.oPDFiD.keywords and self.oPDFiD.keywords[keyword].count > 0:
                results['reasons'].append(reasons[keyword])
                score += 50
        # Auto open/Launch - separated so we do not double-score
        if '/AA' in self.oPDFiD.keywords and self.oPDFiD.keywords['/AA'].count > 0:
            results['reasons'].append(reasons['/AA'])
        if '/OpenAction' in self.oPDFiD.keywords and self.oPDFiD.keywords['/OpenAction'].count > 0:
            results['reasons'].append(reasons['/OpenAction'])
        if '/Launch' in self.oPDFiD.keywords and self.oPDFiD.keywords['/Launch'].count > 0:
            results['reasons'].append(reasons['/Launch'])
        if self.oPDFiD.keywords['/AA'].count > 0 or self.oPDFiD.keywords['/OpenAction'].count > 0 \
                or self.oPDFiD.keywords['/Launch'].count > 0:
            score += 50
        # Forms, Flash, XFA
        for keyword in ('/AcroForm', '/RichMedia', '/XFA'):
            if keyword in self.oPDFiD.keywords and self.oPDFiD.keywords[keyword].count > 0:
                results['reasons'].append(reasons[keyword])
                score += 25
        # Encrypted content
        for keyword in ['/Encrypt']:
            if keyword in self.oPDFiD.keywords and self.oPDFiD.keywords[keyword].count > 0:
                results['reasons'].append(reasons[keyword])
                score += 25
        # Other content to flag for PDFParser to extract, but not to score
        for keyword in ['/Annot']:
            if keyword in self.oPDFiD.keywords and self.oPDFiD.keywords[keyword].count > 0:
                results['reasons'].append(reasons[keyword])
                score += 1
        for keyword in ('/ObjStm',):
            if keyword in self.oPDFiD.keywords and self.oPDFiD.keywords[keyword].count > 0:
                results['reasons'].append(reasons[keyword])
                score += 1
        for keyword in ['/URI']:
            if keyword in self.oPDFiD.keywords and self.oPDFiD.keywords[keyword].count > 0:
                results['reasons'].append(reasons[keyword])
                score += 1

        results['score'] = score

        return results

    def suspicious(self):
        score = 0
        results = {'score': 0, 'reasons': []}
        # Entropy. Typically data outside of streams contain dictionaries & pdf entities (mostly all ASCII text).
        if self.oPDFiD.non_stream_entropy > 6:
            results['reasons'].append('Outside stream entropy of > 5')
            score += 500
        # Pages. Many malicious PDFs will contain only one page.
        if '/Page' in self.oPDFiD.keywords and self.oPDFiD.keywords['/Page'].count == 1:
            results['reasons'].append('Page count of 1')
            score += 50
        # Characters after last %%EOF.
        if self.oPDFiD.last_eof_bytes > 100:
            if self.oPDFiD.last_eof_bytes > 499:
                results['reasons'].append('Over 500 characters after last %%EOF')
                score += 500
            else:
                results['reasons'].append('Over 100 characters after last %%EOF')
                score += 100
        if self.oPDFiD.keywords['obj'].count != self.oPDFiD.keywords['endobj'].count:
            results['reasons'].append('`obj` keyword count does not equal `endobj` keyword count')
            score += 50
        if self.oPDFiD.keywords['stream'].count != self.oPDFiD.keywords['endstream'].count:
            results['reasons'].append('`stream` keyword count does not equal `endstream` count')
            score += 50

        results['score'] = score

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
