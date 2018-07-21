#!/usr/bin/env python

# -*- coding: utf-8 -*-
# This file is part of MaliceIO - https://github.com/malice-plugins/pdf
# See the file 'LICENSE' for copying permission.
import tempfile

__description__ = 'Malice PDF Plugin'
__author__ = 'blacktop - <https://github.com/blacktop>'
__version__ = '0.1.0'
__date__ = '2018/01/29'

import hashlib
import json
import logging
import os

import click

import requests
from elastic import Elastic
from flask import Flask, abort, jsonify, redirect, request, url_for
from jinja2 import BaseLoader, Environment
from pdfid import pdfid
from pdfparser import pdf_parser
from werkzeug.utils import secure_filename

log = logging.getLogger(__name__)


class PDF(object):

    def __init__(self, file_path, verbose):
        self.file = file_path
        self.sha256 = self.sha256_checksum(self.file)
        self.oPDFiD = None
        self.init_logging(verbose)

    @staticmethod
    def init_logging(verbose):
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
        es_logger.addHandler(ch)

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
                    return dict(score=1.0, reason='`/EmbeddedFile` flag(s) are hex encoded')
                else:
                    return dict(score=0.9, reason='`/EmbeddedFile` flag(s) detected')
            else:
                return dict(score=0.0, reason='no `/EmbeddedFile` flag(s) detected')

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

        try:
            self.oPDFiD = pdfid.cPDFiD(pdf_data, force=True)
        except IndexError:
            if not pdf_data.documentElement.getAttribute('IsPDF') == 'True':
                log.error('file cannot be analyzed by PDFiD because it is not a PDF')
                return dict(error='file cannot be analyzed by PDFiD because it is not a PDF')

        # convert to JSON
        pdf_json = pdfid.PDFiD2JSON(pdf_data, True)
        pdf_dict = json.loads(pdf_json)[0]

        # gather PDF heuristics
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

        def get_streams():
            # Initialize pdf parser.
            parser = pdf_parser.cPDFParser(self.file)

            # Generate statistics.
            results = []
            objects = []
            oid = 0

            while True:
                pdf_object = parser.GetObject()
                if pdf_object is None:
                    break
                oid += 1
                objects.append(pdf_object)
                obj_type = pdf_object.type
                obj_id = '/'
                if obj_type == pdf_parser.PDF_ELEMENT_STARTXREF:
                    obj_content = pdf_object.index
                    obj_type = 'STARTXREF'
                elif obj_type == pdf_parser.PDF_ELEMENT_COMMENT:
                    obj_content = pdf_object.comment.encode()
                    obj_type = 'COMMENT'
                elif obj_type in (pdf_parser.PDF_ELEMENT_MALFORMED, pdf_parser.PDF_ELEMENT_TRAILER, pdf_parser.PDF_ELEMENT_XREF,
                                  pdf_parser.PDF_ELEMENT_INDIRECT_OBJECT):
                    obj_content = dump_content(pdf_object.content)
                    if obj_type == pdf_parser.PDF_ELEMENT_MALFORMED:
                        obj_type = 'MALFORMED'
                    elif obj_type == pdf_parser.PDF_ELEMENT_TRAILER:
                        obj_type = 'TRAILER'
                    elif obj_type == pdf_parser.PDF_ELEMENT_XREF:
                        obj_type = 'XREF'
                    elif obj_type == pdf_parser.PDF_ELEMENT_INDIRECT_OBJECT:
                        obj_id = pdf_object.id
                        obj_type = pdf_object.GetType()

                else:
                    # Can it happen?
                    continue

                if isinstance(obj_content, int):
                    obj_len = 0
                else:
                    obj_len = len(obj_content)
                result = [oid, obj_id, obj_len, obj_type]
                # If the stream needs to be dumped or opened, we do it
                # and expand the results with the path to the stream dump.
                if arg_open or arg_dump:
                    # If was instructed to dump, we already have a base folder.
                    if arg_dump:
                        folder = arg_dump
                    # Otherwise we juts generate a temporary one.
                    else:
                        folder = tempfile.gettempdir()

                    # Confirm the dump path
                    if not os.path.exists(folder):
                        try:
                            os.makedirs(folder)
                        except Exception as e:
                            self.log('error', "Unable to create directory at {0}: {1}".format(folder, e))
                            return results
                    else:
                        if not os.path.isdir(folder):
                            self.log('error', "You need to specify a folder not a file")
                            return results
                    if obj_len == 0:
                        continue
                    # Dump stream to this path.
                    dump_path = '{0}/{1}_{2}_pdf_stream.bin'.format(folder, self.sha256, oid)
                    with open(dump_path, 'wb') as handle:
                        handle.write(obj_content)

                    # Add dump path to the stream attributes.
                    result.append(dump_path)
                elif arg_show and int(arg_show) == int(oid):
                    to_print = pdf_parser.FormatOutput(obj_content, True)
                    if isinstance(to_print, int):
                        self.log('info', to_print)
                    else:
                        self.log('info', to_print.decode())
                    if pdf_object.type == pdf_parser.PDF_ELEMENT_INDIRECT_OBJECT and pdf_object.ContainsStream():
                        self.log('Success', 'Stream content:')
                        self.log('info', pdf_parser.FormatOutput(pdf_object.Stream(True), True).decode())

                # Update list of streams.
                results.append(result)
            return sorted(results, key=lambda x: int(x[0]))

        def dump_content(data):
            if isinstance(data, list):
                return b''.join([x[1].encode() for x in data])
            else:
                return data.encode()

        arg_open = True
        arg_dump = 'test/dump'
        arg_show = True

        # Retrieve list of streams.
        streams = get_streams()

        if not arg_show:
            # Show list of streams.
            header = ['#', 'Object ID', 'Size', 'Type']
            if arg_dump or arg_open:
                header.append('Dumped To')

            self.log('table', dict(header=header, rows=streams))

        return {}

    def peepdf(self):
        return {}


def json2markdown(json_data):
    """Convert JSON output to MarkDown table"""

    markdown = '''
#### pdf
{% if pdfid is not none -%}
#### PDFiD
 - **PDF Header:** `{{ pdfid['header'] }}`
 - **Total Entropy:** `{{ pdfid['totalEntropy'] }}`
 - **Entropy In Streams:** `{{ pdfid['streamEntropy'] }}`
 - **Entropy Out Streams:** `{{ pdfid['nonStreamEntropy'] }}`
 - **Count %% EOF:** `{{ pdfid['countEof'] }}`
 - **Data After EOF:** `{{ pdfid['countChatAfterLastEof'] }}`

| Keyword     | Count     |
|-------------|-----------|
{% for keyword in pdfid['keywords'].get('keyword') -%}
| {{ keyword.get('name') }}      | {{ keyword.get('count') }}        |
{% endfor -%}
{% if pdfid['heuristics']['embeddedfile'].get('score') > 0 %}
**Embedded File:**
 - **Score:** `{{ pdfid['heuristics']['embeddedfile'].get('score') }}`
 - **Reason:** {{ pdfid['heuristics']['embeddedfile'].get('reason') }}
{%- endif %}
{% if pdfid['heuristics']['nameobfuscation'].get('score') > 0 -%}
**Name Obfuscation:**
 - **Score:** `{{ pdfid['heuristics']['nameobfuscation'].get('score') }}`
 - **Reason:** {{ pdfid['heuristics']['nameobfuscation'].get('reason') }}
{%- endif %}
{% if pdfid['heuristics']['triage'].get('score') > 0 -%}
**Triage:**
 - **Score:** `{{ pdfid['heuristics']['triage'].get('score') }}`
 - **Reason:** {{ pdfid['heuristics']['triage'].get('reason') }}
{%- endif %}
{%- endif %}
'''

    return Environment(loader=BaseLoader()).from_string(markdown).render(pdfid=json_data.get('pdfid'))


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
    help='proxy settings for Malice webhook endpoint [$MALICE_PROXY]',
    metavar='PROXY')
@click.option(
    '-c',
    '--callback',
    default=lambda: os.environ.get('MALICE_ENDPOINT', ''),
    help='POST results back to Malice webhook [$MALICE_ENDPOINT]',
    metavar='ENDPOINT')
@click.option(
    'eshost',
    '--elasticsearch',
    default=lambda: os.environ.get('MALICE_ELASTICSEARCH', ''),
    help='elasticsearch address for Malice to store results [$MALICE_ELASTICSEARCH]',
    metavar='HOST')
@click.option(
    '--timeout',
    default=lambda: os.environ.get('MALICE_TIMEOUT', 10),
    help='malice plugin timeout (default: 10) [$MALICE_TIMEOUT]',
    metavar='SECS')
def scan(file_path, verbose, table, proxy, callback, eshost, timeout):
    """Malice PDF Plugin."""

    try:
        p = PDF(file_path, verbose)

        pdf_dict = {'pdf': p.pdf_id()}
        # TODO: if PDFiD fails maybe build different response JSON with errors etc.
        pdf_dict['pdf']['streams'] = p.pdf_parser()
        pdf_dict['pdf']['peepdf'] = p.peepdf()
        pdf_dict['pdf']['markdown'] = json2markdown(pdf_dict['pdf'])

        malice_json = {'plugins': {'doc': pdf_dict}}

        # write to elasticsearch
        if eshost:
            e = Elastic(eshost, timeout=timeout)
            e.write(id=p.sha256, doc=malice_json)

        if table:
            print malice_json['plugins']['doc']['pdf']['markdown']
        else:
            print json.dumps(pdf_dict, indent=True)

        if callback:
            requests.post(callback, json=malice_json)

    except Exception as e:
        log.exception("failed to run malice plugin: pdf")
        return


@pdf.command('web', short_help='start web service')
def web():
    """Malice PDF Plugin Web Service"""
    app = Flask(__name__)
    app.config['UPLOAD_FOLDER'] = '/malware'
    # app.config['UPLOAD_FOLDER'] = 'test/web'
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

    @app.errorhandler(400)
    def page_not_found(error):
        return 'Bad requests: you must upload a malware', 400

    @app.errorhandler(500)
    def page_not_found(exception):
        return 'Internal Server Error: \n{}'.format(exception), 500

    @app.route('/scan', methods=['GET', 'POST'])
    def scan():
        if request.method == 'POST':
            # check if the post request has the file part
            if 'malware' not in request.files:
                return redirect(request.url)
            file = request.files['malware']
            # if user does not select file, browser also
            # submit an empty part without filename
            if file.filename == '':
                abort(400)
            if file:
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                try:
                    p = PDF(file_path, logging.INFO)
                    # TODO: if PDFiD fails maybe build different response JSON with errors etc.
                    pdf_dict = {'pdf': p.pdf_id()}
                    pdf_dict['pdf']['streams'] = p.pdf_parser()
                    pdf_dict['pdf']['peepdf'] = p.peepdf()
                    pdf_dict['pdf']['markdown'] = json2markdown(pdf_dict['pdf'])
                    return jsonify(pdf_dict), 200
                except Exception as e:
                    log.exception("failed to run malice plugin: {}".format('pdf'))
                    return e, 500
                finally:
                    try:
                        os.remove(file_path)
                    except OSError as e:
                        log.exception("failed to remove file {} - {}".format(e.filename, e.strerror))

        return "Please upload malware to me... I thirst."

    # start web service
    app.run(host='0.0.0.0', port=3993)


if __name__ == '__main__':
    pdf()
