#!/bin/sh
# End-to-end integration test: 2 trackers + 3 peers on localhost.
# Exercises auth (incl. wrong-password rejection), groups, multi-seeder
# upload/download with an integrity check, and tracker failover.
#
# Usage: tests/integration_test.sh <path-to-build-dir-containing-tracker-and-peer>
#
# Exits 0 and prints "ALL TESTS PASSED" on success; exits 1 with a
# descriptive message on the first failure. Safe to run repeatedly -
# uses a fresh temp directory and cleans up all spawned processes on exit.

set -u

FAIL() {
	echo "FAIL: $1" >&2
	exit 1
}

# Polls instead of a fixed sleep, since an ASan/UBSan-instrumented binary
# can take noticeably longer to start than a normal build.
wait_for_port() {
	port="$1"
	tries=0
	while ! nc -z 127.0.0.1 "$port" 2>/dev/null; do
		tries=$((tries+1))
		[ "$tries" -ge 100 ] && return 1
		sleep 0.1
	done
	return 0
}

# Polls a log file for at least $2 occurrences of "Successful" instead of a
# fixed sleep, for the same reason as wait_for_port above.
wait_for_successes() {
	logfile="$1"
	want="$2"
	tries=0
	while true; do
		count=$(grep -c Successful "$logfile" 2>/dev/null)
		[ -z "$count" ] && count=0
		[ "$count" -ge "$want" ] && return 0
		tries=$((tries+1))
		[ "$tries" -ge 100 ] && return 1
		sleep 0.1
	done
}

BIN="${1:-}"
if [ -z "$BIN" ] || [ ! -x "$BIN/tracker" ] || [ ! -x "$BIN/peer" ]; then
	echo "Usage: $0 <path-to-build-dir-containing-tracker-and-peer>" >&2
	exit 2
fi
BIN=$(cd "$BIN" && pwd)

D=$(mktemp -d /tmp/torrent_integration_test.XXXXXX)
PIDS=""

cleanup() {
	# shellcheck disable=SC2086
	kill -9 $PIDS >/dev/null 2>&1
	rm -rf "$D"
}
trap cleanup EXIT INT TERM

ORIG=$(pwd)
mkdir -p "$D/tracker1" "$D/tracker2" "$D/peer1" "$D/peer2" "$D/peer3" "$D/shared" "$D/certs"
printf "127.0.0.1 27101\n127.0.0.1 27102\n" > "$D/tracker_info.txt"
head -c 3000000 /dev/urandom > "$D/shared/sample.bin"

# Certs live alongside tracker_info.txt (see certs/generate-dev-cert.sh) -
# generate a fresh pair for this isolated test run.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
"$SCRIPT_DIR/../certs/generate-dev-cert.sh" "$D/certs" >/dev/null || FAIL "cert generation failed"

echo "--- starting trackers ---"
cd "$D/tracker1"; "$BIN/tracker" ../tracker_info.txt 1 < /dev/null > t1.log 2>&1 &
t1=$!; PIDS="$PIDS $t1"
cd "$D/tracker2"; "$BIN/tracker" ../tracker_info.txt 2 < /dev/null > t2.log 2>&1 &
t2=$!; PIDS="$PIDS $t2"
cd "$ORIG"
wait_for_port 27101 || FAIL "tracker1 did not start listening in time"
wait_for_port 27102 || FAIL "tracker2 did not start listening in time"

echo "--- auth: create user, reject wrong password, accept correct password ---"
cd "$D/peer1"
# Each of these logs out before quitting: UserLogin only updates the
# tracker's online-peer registration (ip/port) if the user isn't already
# marked online, so a throwaway session that exits without logging out
# would leave the tracker pointing at a dead port - breaking every
# subsequent peer's attempt to fetch chunks from this "seeder".
out=$(printf 'create_user alice pass123\nlogout\nquit\n' | "$BIN/peer" 127.0.0.1 27201 ../tracker_info.txt)
echo "$out" | grep -q "Successful" || FAIL "create_user did not succeed: $out"

out=$(printf 'login alice wrongpass\nquit\n' | "$BIN/peer" 127.0.0.1 27202 ../tracker_info.txt)
echo "$out" | grep -q "Failed" || FAIL "login with wrong password was not rejected: $out"

out=$(printf 'login alice pass123\nlogout\nquit\n' | "$BIN/peer" 127.0.0.1 27203 ../tracker_info.txt)
echo "$out" | grep -q "Successful" || FAIL "login with correct password failed: $out"
cd "$ORIG"

echo "--- seeder 1: persistent login, create group, upload ---"
cd "$D/peer1"
printf 'login alice pass123\ncreate_group demo\nupload_file ../shared/sample.bin demo\n' \
	| "$BIN/peer" 127.0.0.1 27201 ../tracker_info.txt > p1.log 2>&1 &
p1=$!; PIDS="$PIDS $p1"
cd "$ORIG"
wait_for_successes "$D/peer1/p1.log" 3 || FAIL "peer1 login/create_group/upload_file did not all succeed in time: $(cat "$D/peer1/p1.log")"
kill -0 "$p1" 2>/dev/null || FAIL "peer1 (seeder) exited unexpectedly"

echo "--- seeder 2: join, get accepted, upload the same file ---"
cd "$D/peer3"
out=$(printf 'create_user carol pass3\njoin_group demo\nquit\n' | "$BIN/peer" 127.0.0.1 27301 ../tracker_info.txt)
echo "$out" | grep -q "Successful" || FAIL "peer3 create_user/join_group failed: $out"
cd "$ORIG"

cd "$D/peer1"
out=$(printf 'login alice pass123\nlist_requests demo alice\naccept_request demo carol\nquit\n' | "$BIN/peer" 127.0.0.1 27204 ../tracker_info.txt)
echo "$out" | grep -q "carol" || FAIL "carol's join request was not listed: $out"
cd "$ORIG"

cd "$D/peer3"
printf 'login carol pass3\nupload_file ../shared/sample.bin demo\n' | "$BIN/peer" 127.0.0.1 27301 ../tracker_info.txt > p3.log 2>&1 &
p3=$!; PIDS="$PIDS $p3"
cd "$ORIG"
wait_for_successes "$D/peer3/p3.log" 2 || FAIL "peer3 login/upload_file did not all succeed in time: $(cat "$D/peer3/p3.log")"

echo "--- downloader: join, get accepted, download from both seeders in parallel ---"
cd "$D/peer2"
out=$(printf 'create_user bob pass2\njoin_group demo\nquit\n' | "$BIN/peer" 127.0.0.1 27401 ../tracker_info.txt)
echo "$out" | grep -q "Successful" || FAIL "peer2 create_user/join_group failed: $out"
cd "$ORIG"

cd "$D/peer1"
out=$(printf 'login alice pass123\nlist_requests demo alice\naccept_request demo bob\nquit\n' | "$BIN/peer" 127.0.0.1 27205 ../tracker_info.txt)
echo "$out" | grep -q "bob" || FAIL "bob's join request was not listed: $out"
cd "$ORIG"

cd "$D/peer2"
out=$(printf 'login bob pass2\ndownload_file demo sample.bin ./downloaded.bin\nshow_downloads\nlogout\nquit\n' | "$BIN/peer" 127.0.0.1 27401 ../tracker_info.txt)
echo "$out" | grep -q "Full file matched" || FAIL "downloaded file's SHA1 did not match: $out"
echo "$out" | grep -q "\[C\] demo sample.bin" || FAIL "show_downloads did not report the completed download: $out"
cd "$ORIG"

echo "--- independent integrity check ---"
cmp -s "$D/shared/sample.bin" "$D/peer2/downloaded.bin" || FAIL "downloaded file is not byte-identical to the original"

echo "--- tracker failover: kill tracker1, confirm tracker2 has everything ---"
kill -9 "$t1"
# Give tracker2 a moment to notice the connection reset if it was
# mid-recv() on an in-flight sync connection from tracker1 at the exact
# moment it died, rather than racing a fresh request against that.
sleep 0.5
cd "$D/peer2"
out=$(printf 'login bob pass2\nlist_groups\nshow_downloads\nlogout\nquit\n' | "$BIN/peer" 127.0.0.1 27402 ../tracker_info.txt)
echo "$out" | grep -q "demo" || FAIL "tracker2 did not have synced group state after tracker1 died: $out"
echo "$out" | grep -q "\[C\] demo sample.bin" || FAIL "tracker2 did not have synced download history after tracker1 died: $out"
cd "$ORIG"

echo "ALL TESTS PASSED"
