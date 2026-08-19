# Peer to Peer File Transfer (Torrent based File Sharing)

A BitTorrent-style file sharing system built from raw TCP sockets in C++ — no
libtorrent, no external protocol library. Trackers replicate their state to
each other so a client can keep working if one tracker goes down, and peers
download a file in independently-scheduled chunks from whichever seeders hold
them, verifying each chunk's integrity with SHA-1 as it arrives.

Features:
1. Multi-tracker setup with cross-tracker sync and automatic fallback if one goes down.
2. User authentication and per-group file visibility. Passwords are salted
   and SHA-256 hashed on the tracker - never stored or compared in plaintext.
3. The entire tracker control channel (every peer↔tracker exchange, and
   tracker↔tracker sync) runs over TLS, so credentials and state never
   cross the wire in the clear.
4. Piece-selection algorithm that spreads chunk requests across seeders to balance load.
5. Runs on localhost or across real hosts/ports.

## Architecture

```
   +-----------+     state sync      +-----------+
   | tracker 1 | <-----------------> | tracker 2 |
   +-----------+    (every write)    +-----------+
        ^                                  ^
        | login, groups,                   | login, groups,
        | upload, lookup                   | lookup
        |                                  |
   +---------+       +---------+      +-------------+
   | peer A  |       | peer B  |      |   peer C    |
   | seeder  |       | seeder  |      | downloader  |
   +---------+       +---------+      +-------------+
        \                 \                  /
         \_________________\________________/
                 pulls chunks in parallel
                     from peer A and B
```

- **Trackers** hold all shared state (users, groups, which peer has which
  file) as flat text files under `.all_files/`, guarded by a mutex. Every
  write is pushed to the other tracker over a fresh TLS connection
  (`trackersync.cpp`), and a full state dump is exchanged on startup. Peers
  query whichever tracker answers first, so either one can be down.
- **Peers** are both a client (interactive CLI in `peer.cpp`) and a server
  (`peerserver.cpp` listens for chunk requests from other peers). Download
  logic lives in `peerdownload.cpp`.

## Commands

Once logged in (`login`/`create_user`), a peer accepts these on stdin:

| Command | What it does |
|---|---|
| `create_user <user> <pass>` | Sign up, logs you in |
| `login <user> <pass>` | Log in |
| `logout` | Log out |
| `create_group <name>` | Create a group (you're the owner) |
| `list_groups` | List all groups |
| `join_group <name>` | Request to join a group |
| `list_requests <group> <owner>` | List pending join requests (owner only) |
| `accept_request <group> <user>` | Accept a join request (owner only) |
| `leave_group <name>` | Leave a group |
| `upload_file <path> <group>` | Share a file with a group |
| `list_files <group>` | List files shared in a group |
| `stop_share <group> <file>` | Stop sharing a file |
| `download_file <group> <file> <dest>` | Download a file |
| `show_downloads` | List in-progress and completed downloads |
| `quit` | Exit |

## Protocol

Everything is a short, space-separated command sent over its own
connection — no persistent session. Peer↔tracker and tracker↔tracker
traffic is TLS-wrapped with simple length-prefixed framing (`common/tls.cpp`):
a 4-byte length, then the payload. A client opens a TLS connection, sends
one message (e.g. `login alice secret 20001 10.0.0.5`), reads one message
back, and closes it. Tracker-to-tracker `Sync`/`SyncAll` reuses the same TLS
connection for its own lockstep send/ack exchange instead of the
length-prefixed framing, since it streams a whole file back and forth on
one connection rather than a single request/response.

Peer-to-peer chunk requests (`chunk_numbers`, `send_chunk`) are different —
they aren't TLS-wrapped (see [TLS](#tls)), so they're plain TCP: the sender
shuts down its write side after writing, and the other side reads until the
connection closes, since a single `recv()` isn't guaranteed to return a
whole message over TCP.

Files are hashed in fixed 512 KiB chunks (`CHUNK_SIZE`): each chunk gets its
own SHA-1, and those are concatenated into one string that acts as both the
file's identifier and its per-chunk checksum. When downloading, a peer:

1. Asks the tracker who has the file (`give_seeders`) and the expected hash (`give_sha`).
2. Asks every seeder which chunks *they* already have (`chunk_numbers`).
3. Picks, per chunk, the seeder holding the fewest total chunks (spreading
   load toward less-loaded seeders); if every seeder reports "I have
   everything" — the common case for the original uploader(s) — it falls
   back to plain round-robin across them.
4. Downloads each chunk on its own thread, re-requesting it if the received
   bytes don't hash-match, then reports completion back to the tracker.

## TLS

Every connection to a tracker's port - from a peer, or from the sibling
tracker doing `Sync` - is TLS-wrapped (`common/tls.cpp`). This closes the
one gap that mattered most: previously, `login`/`create_user` sent the
password to the tracker in the clear over the wire (it was only hashed
*at rest*, in `.credential.txt`, once it arrived).

This is a self-signed dev certificate (`certs/generate-dev-cert.sh`), not a
real PKI - every peer trusts that one exact certificate directly
("pinning"), rather than a chain of trust from a CA. That's enough to stop
passive network sniffing of credentials and tracker state in transit. It
does **not** protect against an active on-path attacker who can swap in
their own certificate - a real deployment would want a CA-issued cert
instead. Peer-to-peer chunk transfer (the actual file bytes) is unencrypted;
TLS-ing that is a separate piece of work this doesn't cover.

Both trackers share the one cert+key (they're replicas of the same logical
service), so:
- Bare metal: `./initial.sh` generates it once at the project root.
- Docker: a one-shot `certgen` service (see `docker-compose.yml`) generates
  it into a bind-mounted volume before any tracker/peer starts, so every
  separately-built container image reads the identical cert/key from disk
  rather than each generating its own random one.

## Quick start (Docker)

The fastest way to see it working: two trackers and three peers, wired
together on an isolated Docker network with static IPs (so `tracker_info.txt`
just lists real, reachable addresses — no DNS involved).

```
docker compose up -d --build
```

Then attach to a peer to drive it interactively (Ctrl-P Ctrl-Q detaches
without stopping it):

```
docker compose attach peer1
```

Try this walkthrough across a couple of terminals:

```
# in peer1
create_user alice pass123
create_group demo
upload_file /app/tracker_info.txt demo

# in peer2 (docker compose attach peer2)
create_user bob pass123
join_group demo

# back in peer1
list_requests demo alice
accept_request demo bob

# in peer2
list_files demo
download_file demo tracker_info.txt /data/downloaded.txt
show_downloads
```

Drop your own file into `docker/shared/` on the host — it shows up at
`/shared/<name>` inside every peer container, ready to `upload_file`.

Kill `tracker1` (`docker compose stop tracker1`) mid-session and keep going —
everything still works through `tracker2`, since the two trackers
continuously sync state. Bring it all down with `docker compose down`.

## Build from source

Requires CMake (>= 3.10), a C++11 compiler, and OpenSSL development headers.

```
cmake -S . -B build
cmake --build build
```

This produces two executables: `build/tracker` and `build/peer`. Every tracker and every peer runs from the same binary — instances only differ by the command-line arguments they're started with.

### Testing

`tests/integration_test.sh` spins up 2 trackers and 3 peers on localhost in a
temp directory and exercises auth (including that a wrong password is
rejected), groups, a multi-seeder parallel download with an independent
integrity check, and tracker failover. It's wired up via CTest:

```
cd build && ctest --output-on-failure
```

(or run it directly: `tests/integration_test.sh build`)

### Sanitizer build

For development, an ASan+UBSan build catches memory/threading bugs that a
normal build won't (this is how a stack overflow, a startup crash, and an
unguarded data race across download threads were found and fixed in this
codebase). The integration test runs under it the same way, via `ctest`:

```
cmake -S . -B build-asan -DSANITIZE=address,undefined -DCMAKE_BUILD_TYPE=Debug
cmake --build build-asan
cd build-asan && ctest --output-on-failure
```

## Run manually (no Docker)

State (`.all_files/`, downloaded pieces, etc.) is stored relative to each process's working directory, so every tracker/peer instance needs its own directory. `./initial.sh` creates `tracker1/`, `tracker2/`, `peer1/`, `peer2/`, `peer3/` for this, and also generates the shared dev TLS cert (`certs/generate-dev-cert.sh`) that every tracker and peer needs to find at startup - see [TLS](#tls).

1. Edit `tracker_info.txt` with the real IP/port of each tracker (one line per tracker, exactly 2 lines — see `format.txt`).
2. `./initial.sh`
3. Start each tracker from its own directory, passing the tracker info file and the tracker's 1-based index:
   ```
   cd tracker1 && ../build/tracker ../tracker_info.txt 1
   cd tracker2 && ../build/tracker ../tracker_info.txt 2
   ```
4. Start each peer from its own directory, passing its own IP, its listen port, and the tracker info file:
   ```
   cd peer1 && ../build/peer <IP> <PORT> ../tracker_info.txt
   ```
