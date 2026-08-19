#!/bin/sh

# rm -r peer1
# rm -r peer2
# rm -r peer3

# rm -r tracker1
# tm -t tracker2

mkdir -p peer1
mkdir -p peer2
mkdir -p peer3

mkdir -p tracker1/.all_files
mkdir -p tracker2/.all_files

"$(dirname "$0")/certs/generate-dev-cert.sh"