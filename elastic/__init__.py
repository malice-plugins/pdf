# -*- coding: utf-8 -*-
# This file is part of MaliceIO - https://github.com/malice-plugins/pdf
# See the file 'LICENSE' for copying permission.

__description__ = "Malice PDF Plugin Elasticsearch Interface"
__author__ = "blacktop - <https://github.com/blacktop>"

import time

import elasticsearch

from . import mapping


class Elastic(object):

    def __init__(self, elastic_host, timeout=0):
        self.es = elasticsearch.Elasticsearch(elastic_host)

        # wait for elasticsearch to finish starting
        for _ in range(timeout):
            if self.es.ping():
                break
            time.sleep(1)

        if not self.es.ping():
            raise elasticsearch.ElasticsearchException("[PING] cannot connect to host: {}".format(elastic_host))

        # create malice index
        self.es.indices.create(index="malice", ignore=400)
        # self.es.indices.create(index="malice", ignore=400, body=mapping)

    def write(self, id, doc):
        if not self.es.exists(index="malice", doc_type="samples", id=id):
            resp = self.es.index(index="malice", doc_type="samples", id=id, body=doc)
            # {u'_type': u'samples', u'_seq_no': 1, u'_shards': {u'successful': 1, u'failed': 0, u'total': 2},
            # u'_index': u'malice', u'_version': 2, u'_primary_term':1, u'result': u'updated',
            # u'_id': u'86a96ec03ba8242c1486456d67ee17f919128754846dbb3bdf5e836059091dba'}
            if not resp.get("result"):
                raise elasticsearch.ElasticsearchException("[INDEX] failed to write doc with id: {}".format(id))
        else:
            resp = self.es.update(index="malice", doc_type="samples", id=id, body=dict(doc=doc))
            if not resp.get("result"):
                raise elasticsearch.ElasticsearchException("[UPDATE] failed to update doc with id: {}".format(id))
