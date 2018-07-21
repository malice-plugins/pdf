# -*- coding: utf-8 -*-
# This file is part of MaliceIO - https://github.com/malice-plugins/pdf
# See the file 'LICENSE' for copying permission.

import hashlib

from jinja2 import BaseLoader, Environment


def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()


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
