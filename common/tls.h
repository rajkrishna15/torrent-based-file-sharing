#ifndef __common_tls_H_INCLUDED__
#define __common_tls_H_INCLUDED__

#include <openssl/ssl.h>
#include <string>

// One-time OpenSSL library setup. Call once at process startup before any
// other TLS function.
void TLSGlobalInit();

// Server-role context: presents (certfile, keyfile) to connecting clients.
// Exits the process with a clear message if the cert/key can't be loaded
// (most likely: certs/generate-dev-cert.sh hasn't been run yet).
SSL_CTX* TLSServerContext(const std::string& certfile, const std::string& keyfile);

// Client-role context: trusts exactly the certificate at cafile (a
// self-signed dev cert, pinned directly - there is no CA hierarchy here).
// Exits the process with a clear message if cafile can't be loaded.
SSL_CTX* TLSClientContext(const std::string& cafile);

// Wraps an already-accept()'d fd in a TLS server handshake. Returns NULL on
// handshake failure (caller should just close the fd and move on - this is
// expected occasionally, e.g. a liveness probe that connects and
// disconnects without ever speaking TLS).
SSL* TLSAccept(SSL_CTX* ctx, int fd);

// Wraps an already-connect()'d fd in a TLS client handshake. Returns NULL
// on handshake or certificate-verification failure.
SSL* TLSConnect(SSL_CTX* ctx, int fd);

// Sends one length-prefixed message: a 4-byte big-endian length followed by
// the payload. Returns false on any write failure.
bool TLSSendMsg(SSL* ssl, const std::string& data);

// Reads one length-prefixed message written by TLSSendMsg. Returns an empty
// string on any read failure or on a payload length that looks unreasonable
// (a corrupt or non-protocol peer), so callers can treat "empty" uniformly
// as "no valid response" the same way they already do for failed lookups.
std::string TLSRecvMsg(SSL* ssl);

// Sends `data` as-is, no framing - for the tracker-to-tracker Sync file
// stream, which has its own existing chunk/ack framing on top.
bool TLSSendRaw(SSL* ssl, const std::string& data);

// Reads up to maxlen bytes in one SSL_read call, no framing - the
// tracker-to-tracker Sync counterpart to TLSSendRaw.
std::string TLSRecvRaw(SSL* ssl, int maxlen);

// SSL_shutdown + SSL_free. Caller still owns and must close() the fd.
void TLSClose(SSL* ssl);

#endif
