#!/usr/bin/env python

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
import os
import re
import sys
import tempfile
import unicodedata
from logging.handlers import RotatingFileHandler

import click

from elastic import Elastic
from pdfid import pdfid
from pdfparser import pdf_parser

log = logging.getLogger(__name__)


class PDF(object):

    def __init__(self, file_path, verbose):
        self.file = file_path
        self.oPDFiD = None
        self.init_logging(verbose)

    def init_logging(self, verbose):
        # create console handler and set level to debug
        ch = logging.StreamHandler()
        ch.setLevel(verbose)
        ch.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        # add ch to logger
        log.addHandler(ch)

        # get elasticsearch logger
        es_logger = logging.getLogger('elasticsearch')
        es_logger.propagate = False
        es_logger.setLevel(verbose)
        es_logger_handler = RotatingFileHandler('elasticsearch.log', maxBytes=0.5 * 10**9, backupCount=3)
        es_logger.addHandler(es_logger_handler)

        es_tracer = logging.getLogger('elasticsearch.trace')
        es_tracer.propagate = False
        es_tracer.setLevel(verbose)
        es_tracer_handler = RotatingFileHandler('elasticsearch.trace.log', maxBytes=0.5 * 10**9, backupCount=3)
        es_tracer.addHandler(es_tracer_handler)

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


def json2markdown(json_data):
    """Convert JSON output to MarkDown table"""
    pdfid = json_data['plugins']['doc']['pdf']['pdfid']
    print '#### PDF'
    print
    print '#### PDFiD'
    print
    print 'PDF Header: `{}`'.format(pdfid.get('header'))
    print 'Total Entropy: {}'.format(pdfid.get('totalEntropy'))
    print 'Entropy In Streams: {}'.format(pdfid.get('streamEntropy'))
    print 'Entropy Out Streams: {}'.format(pdfid.get('nonStreamEntropy'))
    print 'Count %% EOF: {}'.format(pdfid.get('countEof'))
    print 'Data After EOF: {}'.format(pdfid.get('countChatAfterLastEof'))
    print
    if pdfid['heuristics']['embeddedfile'].get('score') > 0:
        print '**Embedded File:**'
        print ' - Score: {}'.format(pdfid['heuristics']['embeddedfile'].get('score'))
        print ' - Reason: {}'.format(pdfid['heuristics']['embeddedfile'].get('reason'))
    if pdfid['heuristics']['nameobfuscation'].get('score') > 0:
        print '**Name Obfuscation:**'
        print ' - Score: {}'.format(pdfid['heuristics']['nameobfuscation'].get('score'))
        print ' - Reason: {}'.format(pdfid['heuristics']['nameobfuscation'].get('reason'))
    if pdfid['heuristics']['triage'].get('score') > 0:
        print '**Triage:**'
        print ' - Score: {}'.format(pdfid['heuristics']['triage'].get('score'))
        print ' - Reason: {}'.format(pdfid['heuristics']['triage'].get('reason'))
    print
    print '| Keyword     | Count     |'
    print '|-------------|-----------|'
    for keyword in pdfid['keywords'].get('keyword', []):
        print '| {}      | {}        |'.format(keyword.get('name'), keyword.get('count'))


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo('v{}'.format(__version__))
    ctx.exit()


@click.group(context_settings=dict(help_option_names=['-h', '--help']))
@click.option(
    '--version', is_flag=True, callback=print_version, expose_value=False, is_eager=True, help='print the version')
def pdf():
    """Malice PDF Plugin

    Author: blacktop <https://github.com/blacktop>
    """


@pdf.command('scan', short_help='scan a file')
@click.argument('file_path', type=click.Path(exists=True))
@click.option('-v', '--verbose', count=True, help='verbose output')
@click.option('-t', '--table', is_flag=True, help='output as Markdown table')
@click.option(
    '-x',
    '--proxy',
    default=lambda: os.environ.get('MALICE_PROXY', ''),
    help='proxy settings for Malice webhook endpoint',
    metavar='PROXY')
@click.option(
    '-c',
    '--callback',
    default=lambda: os.environ.get('MALICE_ENDPOINT', ''),
    help='POST results back to Malice webhook',
    metavar='ENDPOINT')
@click.option(
    'eshost',
    '--elasticsearch',
    default=lambda: os.environ.get('MALICE_ELASTICSEARCH', {'host': 'elasticsearch'}),
    help='elasticsearch address for Malice to store results',
    metavar='HOST')
def scan(file_path, verbose, table, proxy, callback, eshost):
    """Malice PDF Plugin."""

    try:
        p = PDF(file_path, verbose)

        pdf_dict = {'pdf': p.pdf_id()}
        pdf_dict['pdf']['streams'] = p.pdf_parser()
        pdf_dict['pdf']['peepdf'] = p.peepdf()

        malice_json = {'plugins': {'doc': pdf_dict}}

        # write to elasticsearch
        e = Elastic(eshost)
        e.write(id=p.sha256_checksum(p.file), doc=malice_json)

        if table:
            json2markdown(malice_json)
        else:
            print json.dumps(malice_json)

    except Exception as e:
        log.exception("failed to run malice plugin: {}".format('pdf'))
        return


@pdf.command('web', short_help='start web service')
def web():
    click.secho('This has not been implimented yet.', fg='yellow', bold=True)


if __name__ == '__main__':
    pdf()
