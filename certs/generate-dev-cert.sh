#!/bin/sh
# Generates a self-signed cert+key pair for the tracker's TLS listener.
#
# This is NOT a real PKI: there's no CA, and every peer trusts this exact
# certificate directly ("pinning"), not a chain of trust. That's enough to
# stop passive network sniffing of credentials/state in transit between
# peers and trackers, and between the two trackers - it does NOT protect
# against someone who can swap in their own cert on the wire (an active
# on-path attacker). For that you'd want a real CA-issued cert.
#
# Both trackers (tracker1 and tracker2) share this one cert+key, since
# they're replicas of the same logical service - a peer just needs to
# trust "the tracker", not tracker1 and tracker2 individually.
#
# Usage: certs/generate-dev-cert.sh [output-dir, default: this script's dir]

set -e

OUT="${1:-$(cd "$(dirname "$0")" && pwd)}"

if [ -f "$OUT/tracker.crt" ] && [ -f "$OUT/tracker.key" ]; then
	echo "Certs already exist at $OUT - remove them first if you want to regenerate."
	exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes \
	-keyout "$OUT/tracker.key" \
	-out "$OUT/tracker.crt" \
	-days 365 \
	-subj "/CN=torrent-tracker" \
	-addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "Generated $OUT/tracker.crt and $OUT/tracker.key"
