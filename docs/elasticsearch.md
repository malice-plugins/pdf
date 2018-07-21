# To write results to [ElasticSearch](https://www.elastic.co/products/elasticsearch)

## Requirements

- [blacktop/elasticsearch:5.5](https://github.com/blacktop/docker-elasticsearch-alpine)

> **NOTE:** limited to **elasticsearch:5.5** for now because that is what **malice** uses

```bash
# I am creating a volume to store the elasticsearch data incase the container dies (or we upgrade later)
$ docker volume create --name malice
$ docker run -d --name elasticsearch \
                -p 9200:9200 \
                -v malice:/usr/share/elasticsearch/data \
                 blacktop/elasticsearch
$ docker run --rm \
             -v /path/to/malware:/malware:ro \
             --link elasticsearch \
             malice/pdf -t --elasticsearch elasticsearch PDF_FILE
```
