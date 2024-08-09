FROM ubuntu:22.04 as build

RUN DEBIAN_FRONTEND=noninteractive apt-get update -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential libbenchmark-dev libomp-dev libgmp-dev \ 
    nlohmann-json3-dev postgresql libpqxx-dev libpqxx-doc nasm \
    libsecp256k1-dev libcurl4-openssl-dev libsodium-dev libprotobuf-dev libssl-dev \
    cmake s3cmd libgrpc++-dev protobuf-compiler protobuf-compiler-grpc uuid-dev && \
    rm -fr /var/cache/apt/*

WORKDIR /usr/src/app

COPY ./src ./src

WORKDIR /usr/src/app/src/grpc
RUN make

WORKDIR /usr/src/app

COPY ./test ./test
COPY ./tools ./tools
COPY Makefile .
RUN make -j


FROM ubuntu:22.04 as executor

WORKDIR /app
COPY ./testvectors ./testvectors
COPY ./config ./config
COPY ./src/main_sm/fork_1/scripts/rom.json ./src/main_sm/fork_1/scripts/rom.json
COPY ./src/main_sm/fork_2/scripts/rom.json ./src/main_sm/fork_2/scripts/rom.json
COPY ./src/main_sm/fork_3/scripts/rom.json ./src/main_sm/fork_3/scripts/rom.json
COPY ./src/main_sm/fork_4/scripts/rom.json ./src/main_sm/fork_4/scripts/rom.json
COPY ./src/main_sm/fork_5/scripts/rom.json ./src/main_sm/fork_5/scripts/rom.json
COPY ./src/main_sm/fork_6/scripts/rom.json ./src/main_sm/fork_6/scripts/rom.json

RUN DEBIAN_FRONTEND=noninteractive apt update && \
    DEBIAN_FRONTEND=noninteractive apt install -y \ 
    build-essential libbenchmark-dev libomp-dev libgmp-dev \ 
    nlohmann-json3-dev postgresql libpqxx-dev libpqxx-doc nasm \
    libsecp256k1-dev libcurl4-openssl-dev libsodium-dev libprotobuf-dev libssl-dev \
    cmake s3cmd libgrpc++-dev protobuf-compiler protobuf-compiler-grpc uuid-dev && \
    rm -fr /var/cache/apt/*

COPY --from=build /usr/src/app/build/zkProver /usr/local/bin/zkProver

ENTRYPOINT []


FROM executor as prover

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y awscli s3cmd && \
    rm -fr /var/cache/apt/*
WORKDIR /app/config

WORKDIR /app

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

ENV PATH=$HOME/.cargo/bin:$PATH

RUN cargo install --git https://github.com/gevulotnetwork/gevulot.git gevulot-cli

RUN mkdir inputs

ENV AWS_ACCESS_KEY_ID=your_access_key
ENV AWS_SECRET_ACCESS_KEY=your_secret_key
ENV AWS_DEFAULT_REGION=your_aws_region

RUN echo -e "[default]\n\
access_key = $AWS_ACCESS_KEY_ID\n\
secret_key = $AWS_SECRET_ACCESS_KEY\n\
bucket_location = $AWS_DEFAULT_REGION\n\
region = $AWS_DEFAULT_REGION\n\
use_https = True\n\
host_base = s3.$AWS_DEFAULT_REGION.amazonaws.com\n\
host_bucket = %(bucket)s.s3.$AWS_DEFAULT_REGION.amazonaws.com\n\
signature_v2 = False\n\
signature_v4 = True\n" > $HOME/.s3cfg

ENTRYPOINT []
