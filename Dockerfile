FROM malice/alpine

LABEL maintainer "https://github.com/blacktop"

LABEL malice.plugin.repository = "https://github.com/malice-plugins/pdf.git"
LABEL malice.plugin.category="pdf"
LABEL malice.plugin.mime="application/pdf"
LABEL malice.plugin.docker.engine="*"

ENV PDFID 0_2_4
ENV PDF_PARSER 0_6_8

COPY . /src/github.com/maliceio/malice-pdf
RUN apk --update add --no-cache python py-setuptools
RUN apk --update add --no-cache -t .build-deps \
  openssl-dev \
  build-base \
  python-dev \
  libffi-dev \
  musl-dev \
  libc-dev \
  py-pip \
  gcc \
  git \
  && set -ex \
  && echo "===> Install peepdf..." \
  && cd /src/github.com/maliceio/malice-pdf \
  && export PIP_NO_CACHE_DIR=off \
  && export PIP_DISABLE_PIP_VERSION_CHECK=on \
  && pip install --upgrade pip wheel \
  && echo "\t[*] install requirements..." \
  && pip install -U -r requirements.txt \
  && echo "\t[*] install requirements..." \
  && pip install https://github.com/jbremer/peepdf.git \
  && echo "\t[*] install pdfscan.py..." \
  && chmod +x pdfscan.py \
  && ln -s /src/github.com/maliceio/malice-pdf/pdfscan.py /bin/pdfscan \
  && apk del --purge .build-deps

WORKDIR /malware

ENTRYPOINT ["su-exec","malice","/sbin/tini","--","pdfid.py"]
CMD ["--help"]
