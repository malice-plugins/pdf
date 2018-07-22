#!/usr/bin/env python
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

import click
import requests
from flask import Flask, abort, jsonify, redirect, request
from werkzeug.utils import secure_filename

from elastic import Elastic
from pdfid.malice_pdfid import MalPDFiD
from pdfparser.malice_pdfparser import MalPdfParser
from utils import json2markdown, sha256_checksum

log = logging.getLogger(__name__)


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
@click.option(
    '--extract',
    default=lambda: os.environ.get('MALICE_EXTRACT_PATH', '/malware/dump'),
    help='where to extract the embedded objects to',
    metavar='PATH')
def scan(file_path, verbose, table, proxy, callback, eshost, timeout, extract):
    """Malice PDF Plugin."""

    pdf_results = {
        'pdf': {
            'pdfid': {},
            'streams': {},
            'heuristics': {},
            'markdown': "",
        }
    }

    try:
        # set up logging
        init_logging(verbose)

        # TODO: if PDFiD fails maybe build different response JSON with errors etc.
        pdf_results['pdf']['pdfid'] = MalPDFiD(file_path).run()
        pdf_results['pdf']['streams'] = MalPdfParser(file_path, extract, pdf_results['pdf']['pdfid']).run()
        # pdf_dict['pdf']['peepdf'] = MalPeepdf(file_path).run()
        pdf_results['pdf']['markdown'] = json2markdown(pdf_results['pdf'])
        malice_json = {'plugins': {'doc': pdf_results}}

        # write to elasticsearch
        if eshost:
            e = Elastic(eshost, timeout=timeout)
            e.write(id=sha256_checksum(file_path), doc=malice_json)

        if table:
            print(malice_json['plugins']['doc']['pdf']['markdown'])
        else:
            print(json.dumps(pdf_results, indent=True))

        if callback:
            # TODO: use proxy
            requests.post(callback, json=malice_json)

    except Exception as e:
        log.exception("failed to run malice plugin: pdf")
        return


@pdf.command('web', short_help='start web service')
def web():
    """Malice PDF Plugin Web Service"""

    # set up logging
    init_logging(logging.ERROR)

    app = Flask(__name__)
    app.config['UPLOAD_FOLDER'] = '/malware'
    app.config['OUTPUT_FOLDER'] = '/malware/dump'
    # app.config['UPLOAD_FOLDER'] = 'test/web'
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

    @app.errorhandler(400)
    def bad_request(error):
        return 'Bad requests: you must upload a malware', 400

    @app.errorhandler(500)
    def server_error(exception):
        return 'Internal Server Error: \n{}'.format(exception), 500

    @app.route('/scan', methods=['GET', 'POST'])
    def upload():
        if request.method == 'POST':
            # check if the post request has the file part
            if 'malware' not in request.files:
                return redirect(request.url)
            upload_file = request.files['malware']
            # if user does not select file, browser also
            # submit an empty part without filename
            if upload_file.filename == '':
                abort(400)
            if upload_file:
                filename = secure_filename(upload_file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                upload_file.save(file_path)
                try:
                    pdf_results = {
                        'pdf': {
                            'pdfid': {},
                            'streams': {},
                            'heuristics': {},
                            'markdown': "",
                        }
                    }
                    pdf_results['pdf']['pdfid'] = MalPDFiD(file_path).run()
                    pdf_results['pdf']['streams'] = MalPdfParser(file_path, app.config['OUTPUT_FOLDER']).run()
                    # pdf_dict['pdf']['peepdf'] = MalPeepdf(file_path).run()
                    pdf_results['pdf']['markdown'] = json2markdown(pdf_results['pdf'])
                    return jsonify(pdf_results), 200
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
