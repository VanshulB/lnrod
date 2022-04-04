# Integration test
# NOTE: incomplete - does not build vlsd

FROM python:latest
#FROM python@sha256:07c51c65ab9c1a156a1fb51eff3ec04feff7b85b2acb7d6cc65148b218d67402

WORKDIR /usr/src/app

COPY ../requirements.txt .
RUN pip3 install -r requirements.txt

RUN wget --no-verbose https://bitcoin.org/bin/bitcoin-core-0.21.0/bitcoin-0.21.0-x86_64-linux-gnu.tar.gz
RUN echo da7766775e3f9c98d7a9145429f2be8297c2672fe5b118fd3dc2411fb48e0032  bitcoin-0.21.0-x86_64-linux-gnu.tar.gz | sha256sum -c
RUN tar xzf bitcoin-0.21.0-x86_64-linux-gnu.tar.gz && \
  mv bitcoin-0.21.0/bin/bitcoind /usr/local/bin && \
  rm -rf bitcoin-0.21.0


COPY ../scripts scripts

COPY ../target/debug/lnrod target/debug/
COPY ../src/admin/admin.proto src/admin/
COPY ../tests tests

RUN ./scripts/compile-proto

ENTRYPOINT ["./tests/integration-test.py"]
