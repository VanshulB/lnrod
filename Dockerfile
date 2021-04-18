# Integration test

FROM rust:1.49.0

WORKDIR /usr/src/app

RUN apt update
RUN apt -y install python3-pip

COPY requirements.txt .
RUN pip3 install -r requirements.txt

RUN wget --no-verbose https://bitcoin.org/bin/bitcoin-core-0.21.0/bitcoin-0.21.0-x86_64-linux-gnu.tar.gz
RUN echo da7766775e3f9c98d7a9145429f2be8297c2672fe5b118fd3dc2411fb48e0032  bitcoin-0.21.0-x86_64-linux-gnu.tar.gz | sha256sum -c
RUN tar xzf bitcoin-0.21.0-x86_64-linux-gnu.tar.gz && \
  mv bitcoin-0.21.0/bin/bitcoind /usr/local/bin && \
  rm -rf bitcoin-0.21.0

# create a layer with crates.io index
COPY misc/Cargo.toml-simple Cargo.toml
RUN mkdir src
COPY misc/main.rs src/
RUN cargo build

COPY . .
RUN cargo build

ENTRYPOINT ["./tests/integration-test.py"]
