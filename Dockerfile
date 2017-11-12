FROM malice/alpine

LABEL maintainer "https://github.com/blacktop"

LABEL malice.plugin.repository = "https://github.com/malice-plugins/pdf.git"
LABEL malice.plugin.category="pdf"
LABEL malice.plugin.mime="application/pdf"
LABEL malice.plugin.docker.engine="*"

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
  && echo "===> Install PDF Scanner..." \
  && cd /src/github.com/maliceio/malice-pdf \
  && export PIP_NO_CACHE_DIR=off \
  && export PIP_DISABLE_PIP_VERSION_CHECK=on \
  && pip install --upgrade pip wheel \
  && echo " [*] Install requirements..." \
  # && pip install -U -r requirements.txt \
  && chmod +x pdf.py \
  && ln -s /src/github.com/maliceio/malice-pdf/pdf.py /bin/pdfscan \
  && apk del --purge .build-deps

WORKDIR /malware

ENTRYPOINT ["su-exec","malice","/sbin/tini","--","pdfscan"]
CMD ["--help"]
