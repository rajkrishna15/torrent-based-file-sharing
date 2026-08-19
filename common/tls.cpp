#include "tls.h"

#include <openssl/err.h>
#include <arpa/inet.h>
#include <iostream>
#include <csignal>

using namespace std;

#define MAX_MSG_SIZE (16*1024*1024)

void TLSGlobalInit(){
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	// Writing to a socket whose peer already closed its end (e.g. an
	// SSL_shutdown close-notify racing the other side's own close())
	// raises SIGPIPE, whose default disposition kills the whole process.
	// Ignore it so those writes just fail with EPIPE instead, which the
	// TLSSendMsg/TLSSendRaw <= 0 checks already treat as a normal failure.
	signal(SIGPIPE,SIG_IGN);
}

SSL_CTX* TLSServerContext(const string& certfile, const string& keyfile){
	SSL_CTX* ctx=SSL_CTX_new(TLS_server_method());
	if(!ctx){
		cerr<<"Failed to create TLS server context"<<endl;
		exit(-1);
	}

	if(SSL_CTX_use_certificate_file(ctx,certfile.c_str(),SSL_FILETYPE_PEM)<=0){
		cerr<<"Failed to load TLS certificate: "<<certfile<<endl;
		cerr<<"Run certs/generate-dev-cert.sh to generate one."<<endl;
		exit(-1);
	}

	if(SSL_CTX_use_PrivateKey_file(ctx,keyfile.c_str(),SSL_FILETYPE_PEM)<=0){
		cerr<<"Failed to load TLS private key: "<<keyfile<<endl;
		cerr<<"Run certs/generate-dev-cert.sh to generate one."<<endl;
		exit(-1);
	}

	return ctx;
}

SSL_CTX* TLSClientContext(const string& cafile){
	SSL_CTX* ctx=SSL_CTX_new(TLS_client_method());
	if(!ctx){
		cerr<<"Failed to create TLS client context"<<endl;
		exit(-1);
	}

	if(SSL_CTX_load_verify_locations(ctx,cafile.c_str(),NULL)<=0){
		cerr<<"Failed to load trusted TLS certificate: "<<cafile<<endl;
		cerr<<"Run certs/generate-dev-cert.sh to generate one."<<endl;
		exit(-1);
	}

	SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);

	return ctx;
}

SSL* TLSAccept(SSL_CTX* ctx,int fd){
	SSL* ssl=SSL_new(ctx);
	SSL_set_fd(ssl,fd);

	if(SSL_accept(ssl)<=0){
		SSL_free(ssl);
		return NULL;
	}

	return ssl;
}

SSL* TLSConnect(SSL_CTX* ctx,int fd){
	SSL* ssl=SSL_new(ctx);
	SSL_set_fd(ssl,fd);

	if(SSL_connect(ssl)<=0){
		SSL_free(ssl);
		return NULL;
	}

	return ssl;
}

static bool SSLWriteAll(SSL* ssl,const char* data,size_t len){
	size_t sent=0;
	while(sent<len){
		int n=SSL_write(ssl,data+sent,len-sent);
		if(n<=0)
			return false;
		sent+=n;
	}
	return true;
}

static bool SSLReadAll(SSL* ssl,char* buf,size_t len){
	size_t got=0;
	while(got<len){
		int n=SSL_read(ssl,buf+got,len-got);
		if(n<=0)
			return false;
		got+=n;
	}
	return true;
}

bool TLSSendMsg(SSL* ssl,const string& data){
	uint32_t len=htonl((uint32_t)data.size());

	if(!SSLWriteAll(ssl,(const char*)&len,sizeof(len)))
		return false;
	if(data.size()>0 && !SSLWriteAll(ssl,data.data(),data.size()))
		return false;

	return true;
}

string TLSRecvMsg(SSL* ssl){
	uint32_t len_net;
	if(!SSLReadAll(ssl,(char*)&len_net,sizeof(len_net)))
		return "";

	uint32_t len=ntohl(len_net);
	if(len>MAX_MSG_SIZE)
		return "";
	if(len==0)
		return "";

	string result(len,'\0');
	if(!SSLReadAll(ssl,&result[0],len))
		return "";

	return result;
}

bool TLSSendRaw(SSL* ssl,const string& data){
	return SSLWriteAll(ssl,data.data(),data.size());
}

string TLSRecvRaw(SSL* ssl,int maxlen){
	string buf(maxlen,'\0');
	int n=SSL_read(ssl,&buf[0],maxlen);
	if(n<=0)
		return "";
	buf.resize(n);
	return buf;
}

void TLSClose(SSL* ssl){
	if(!ssl)
		return;
	SSL_shutdown(ssl);
	SSL_free(ssl);
}
