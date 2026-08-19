FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ cmake make libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY CMakeLists.txt ./
COPY tracker ./tracker
COPY peer ./peer
COPY common ./common

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build -j"$(nproc)"

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/build/tracker /app/tracker
COPY --from=build /src/build/peer /app/peer
COPY docker/tracker_info.txt /app/tracker_info.txt
COPY README.md /app/README.md

# Every tracker/peer container in the demo must present/trust the exact
# same cert (see certs/generate-dev-cert.sh) - generating it independently
# per container (e.g. at image build time) would give each one a different
# random keypair, since docker-compose tags this Dockerfile as a separate
# image per service. Instead, the "certgen" service in docker-compose.yml
# runs this script once at container start into a shared bind-mounted
# volume, so every service reads the identical cert/key files from disk.
COPY certs/generate-dev-cert.sh /app/generate-dev-cert.sh

WORKDIR /data
