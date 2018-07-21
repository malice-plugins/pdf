# Usage:
#
# docker build --rm --force-rm -t peepdf .
#
# docker run --name=peepdf -v /tmp/pdf:/opt/pdf --rm -it peepdf
#

FROM ubuntu:14.04
MAINTAINER Sn0rkY <snorky@insomnihack.net>

# Update & upgrade
RUN apt-get update && apt-get upgrade -y

# Install Dependencies
RUN buildDeps=' \
    ca-certificates \
    python \
    python-dev \
    git \
    subversion \
    make \
    gcc \
    g++ \
    pkg-config \
    libboost-thread-dev \
    libboost-system-dev \
    libboost-python-dev \
    python-libemu \
    python-lxml \
    ' \
    && set -x \
    && apt-get install -y $buildDeps --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Set Working directory
WORKDIR /opt

# PyV8 Dependencie for peepdf
RUN svn checkout http://pyv8.googlecode.com/svn/trunk/ pyv8-read-only \
    && cd pyv8-read-only \
    && python setup.py build \
    && sudo python setup.py install

## Clone PEEPDF repo
RUN git clone https://github.com/jesparza/peepdf/

# Set peepdf directory
WORKDIR /opt/peepdf