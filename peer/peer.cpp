#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <string>
#include <vector>
#include <set>
#include <stdio.h>
#include <stdlib.h>
#include <utility>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include "tls.h"
#include "peerserver.h"
#include "peerdownload.h"

using namespace std;

#define MAX_SIZE 65535
#define CHUNK_SIZE 524288

string username;
string myip;

string si="";//="127.0.0.1";
int sp=0;//=10001;

// Client-role TLS context: trusts the tracker's cert directly (there's no
// CA hierarchy here - see certs/generate-dev-cert.sh).
SSL_CTX* tracker_ctx;

unordered_map<string,vector<int>> filechunks_map;
// Guards filechunks_map: concurrent DownloadKernel threads append to it
// while ClientServerKernel threads may read it to answer chunk_numbers
// requests from other peers for a file this peer is still downloading.
pthread_mutex_t filechunks_lock=PTHREAD_MUTEX_INITIALIZER;

// A single recv() isn't guaranteed to return a whole message over TCP.
// The peer being read from always shuts down its write side (or closes
// outright, for fire-and-forget sends) right after writing, so looping
// until recv() reports EOF safely collects the complete message either way.
string RecvAll(int sock){
	string result="";
	char buf[MAX_SIZE+1];
	int n;

	while((n=recv(sock,buf,MAX_SIZE,0))>0){
		result.append(buf,n);
	}

	return result;
}

bool CheckTracker(string filepath){
	ifstream infile(filepath,ios::in);
	string line;

	struct sockaddr_in remote_server;
	int sock;
	bool flag=false;

	while(getline(infile,line)){
		auto split_vector=split(line,' ');
		// cout<<split_vector[0]<<endl;
		// cout<<split_vector[1]<<endl;

		if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
			perror("socket");
			// exit(-1);
		}

		remote_server.sin_family=AF_INET;
		remote_server.sin_port=htons(atoi(split_vector[1].c_str()));
		remote_server.sin_addr.s_addr=inet_addr(split_vector[0].c_str());
		bzero(&remote_server.sin_zero,8);

		if(!((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1)){
			// perror("connect");
			// exit(-1);
			flag=true;
			si=split_vector[0];
			sp=atoi(split_vector[1].c_str());

			close(sock);
		}
	}

	// cout<<"Connected to "<<sp<<endl;
	return flag;
}

bool UserLogin(string username,string password,int myport_i){
	struct sockaddr_in remote_server;
	int sock;
	char output[MAX_SIZE];

	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
		perror("socket");
		exit(-1);
	}

	remote_server.sin_family=AF_INET;
	remote_server.sin_port=htons(sp);
	remote_server.sin_addr.s_addr=inet_addr(si.c_str());
	bzero(&remote_server.sin_zero,8);

	if((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1){
		perror("connect");
		exit(-1);
	}

	SSL* ssl=TLSConnect(tracker_ctx,sock);
	if(!ssl){
		cerr<<"TLS handshake with tracker failed"<<endl;
		close(sock);
		return false;
	}

	string data="login "+username+" "+password+" "+to_string(myport_i)+" "+myip;
	TLSSendMsg(ssl,data);
	string output_str=TLSRecvMsg(ssl);
	TLSClose(ssl);
	size_t copy_len=output_str.size()<MAX_SIZE-1?output_str.size():MAX_SIZE-1;
	memcpy(output,output_str.c_str(),copy_len);
	output[copy_len]='\0';
	// cout<<output<<endl;

	if(output[0]=='0')
		return false;
	else
		return true;
}

bool UserCreate(string username,string password,int myport_i){
	struct sockaddr_in remote_server;
	int sock;
	char output[MAX_SIZE];

	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
		perror("socket");
		exit(-1);
	}

	remote_server.sin_family=AF_INET;
	remote_server.sin_port=htons(sp);
	remote_server.sin_addr.s_addr=inet_addr(si.c_str());
	bzero(&remote_server.sin_zero,8);

	if((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1){
		perror("connect");
		exit(-1);
	}

	SSL* ssl=TLSConnect(tracker_ctx,sock);
	if(!ssl){
		cerr<<"TLS handshake with tracker failed"<<endl;
		close(sock);
		return false;
	}

	string data="create_user "+username+" "+password+" "+to_string(myport_i)+" "+myip;
	TLSSendMsg(ssl,data);
	string output_str=TLSRecvMsg(ssl);
	TLSClose(ssl);
	size_t copy_len=output_str.size()<MAX_SIZE-1?output_str.size():MAX_SIZE-1;
	memcpy(output,output_str.c_str(),copy_len);
	output[copy_len]='\0';
	// cout<<output<<endl;

	close(sock);

	if(output[0]=='0')
		return false;
	else
		return true;
}

bool GroupCreate(string groupname, string username){
	// cout<<groupname<<endl;
	// cout<<username<<endl;

	struct sockaddr_in remote_server;
	int sock;
	char output[MAX_SIZE];

	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
		perror("socket");
		exit(-1);
	}

	remote_server.sin_family=AF_INET;
	remote_server.sin_port=htons(sp);
	remote_server.sin_addr.s_addr=inet_addr(si.c_str());
	bzero(&remote_server.sin_zero,8);

	if((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1){
		perror("connect");
		exit(-1);
	}

	SSL* ssl=TLSConnect(tracker_ctx,sock);
	if(!ssl){
		cerr<<"TLS handshake with tracker failed"<<endl;
		close(sock);
		return false;
	}

	string data="create_group "+groupname+" "+username;
	TLSSendMsg(ssl,data);
	string output_str=TLSRecvMsg(ssl);
	TLSClose(ssl);
	size_t copy_len=output_str.size()<MAX_SIZE-1?output_str.size():MAX_SIZE-1;
	memcpy(output,output_str.c_str(),copy_len);
	output[copy_len]='\0';
	// cout<<output<<endl;

	close(sock);

	if(output[0]=='0')
		return false;
	else{
		// ofstream outfile(,ios::out);
		// outfile<<username<<endl;
		return true;
	}
}

void GroupList(){
	struct sockaddr_in remote_server;
	int sock;
	char output[MAX_SIZE];

	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
		perror("socket");
		exit(-1);
	}

	remote_server.sin_family=AF_INET;
	remote_server.sin_port=htons(sp);
	remote_server.sin_addr.s_addr=inet_addr(si.c_str());
	bzero(&remote_server.sin_zero,8);

	if((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1){
		perror("connect");
		exit(-1);
	}

	SSL* ssl=TLSConnect(tracker_ctx,sock);
	if(!ssl){
		cerr<<"TLS handshake with tracker failed"<<endl;
		close(sock);
		return;
	}

	string data="list_groups";
	TLSSendMsg(ssl,data);
	string output_str=TLSRecvMsg(ssl);
	TLSClose(ssl);
	size_t copy_len=output_str.size()<MAX_SIZE-1?output_str.size():MAX_SIZE-1;
	memcpy(output,output_str.c_str(),copy_len);
	output[copy_len]='\0';
	cout<<"##### List of Groups #####"<<endl<<endl;
	cout<<output<<endl;

	cout<<"#####  #####"<<endl;

	close(sock);
}

bool GroupJoin(string groupname,string username){
	struct sockaddr_in remote_server;
	int sock;
	char output[MAX_SIZE];

	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
		perror("socket");
		exit(-1);
	}

	remote_server.sin_family=AF_INET;
	remote_server.sin_port=htons(sp);
	remote_server.sin_addr.s_addr=inet_addr(si.c_str());
	bzero(&remote_server.sin_zero,8);

	if((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1){
		perror("connect");
		exit(-1);
	}

	SSL* ssl=TLSConnect(tracker_ctx,sock);
	if(!ssl){
		cerr<<"TLS handshake with tracker failed"<<endl;
		close(sock);
		return false;
	}

	string data="join_group "+groupname+" "+username;
	TLSSendMsg(ssl,data);
	string output_str=TLSRecvMsg(ssl);
	TLSClose(ssl);
	size_t copy_len=output_str.size()<MAX_SIZE-1?output_str.size():MAX_SIZE-1;
	memcpy(output,output_str.c_str(),copy_len);
	output[copy_len]='\0';
	// cout<<output<<endl;

	close(sock);

	if(output[0]=='0')
		return false;
	else
		return true;
}

void GroupRequestList(string groupname,string username){
	struct sockaddr_in remote_server;
	int sock;
	char output[MAX_SIZE];

	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
		perror("socket");
		exit(-1);
	}

	remote_server.sin_family=AF_INET;
	remote_server.sin_port=htons(sp);
	remote_server.sin_addr.s_addr=inet_addr(si.c_str());
	bzero(&remote_server.sin_zero,8);

	if((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1){
		perror("connect");
		exit(-1);
	}

	SSL* ssl=TLSConnect(tracker_ctx,sock);
	if(!ssl){
		cerr<<"TLS handshake with tracker failed"<<endl;
		close(sock);
		return;
	}

	string data="list_requests "+groupname+" "+username;
	TLSSendMsg(ssl,data);
	string output_str=TLSRecvMsg(ssl);
	TLSClose(ssl);
	size_t copy_len=output_str.size()<MAX_SIZE-1?output_str.size():MAX_SIZE-1;
	memcpy(output,output_str.c_str(),copy_len);
	output[copy_len]='\0';

	cout<<"##### List of Requests #####"<<endl<<endl;
	cout<<output<<endl;

	cout<<"#####  #####"<<endl;

	close(sock);
}

void GroupRequestFiles(string groupname){
	struct sockaddr_in remote_server;
	int sock;
	char output[MAX_SIZE];

	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
		perror("socket");
		exit(-1);
	}

	remote_server.sin_family=AF_INET;
	remote_server.sin_port=htons(sp);
	remote_server.sin_addr.s_addr=inet_addr(si.c_str());
	bzero(&remote_server.sin_zero,8);

	if((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1){
		perror("connect");
		exit(-1);
	}

	SSL* ssl=TLSConnect(tracker_ctx,sock);
	if(!ssl){
		cerr<<"TLS handshake with tracker failed"<<endl;
		close(sock);
		return;
	}

	string data="list_files "+groupname;
	TLSSendMsg(ssl,data);
	string output_str=TLSRecvMsg(ssl);
	TLSClose(ssl);
	size_t copy_len=output_str.size()<MAX_SIZE-1?output_str.size():MAX_SIZE-1;
	memcpy(output,output_str.c_str(),copy_len);
	output[copy_len]='\0';

	cout<<"##### List of Files #####"<<endl<<endl;
	cout<<output<<endl;

	cout<<"#####  #####"<<endl;

	close(sock);
}

bool GroupAcceptRequest(string groupname,string username1,string username){
	struct sockaddr_in remote_server;
	int sock;
	char output[MAX_SIZE];

	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
		perror("socket");
		exit(-1);
	}

	remote_server.sin_family=AF_INET;
	remote_server.sin_port=htons(sp);
	remote_server.sin_addr.s_addr=inet_addr(si.c_str());
	bzero(&remote_server.sin_zero,8);

	if((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1){
		perror("connect");
		exit(-1);
	}

	SSL* ssl=TLSConnect(tracker_ctx,sock);
	if(!ssl){
		cerr<<"TLS handshake with tracker failed"<<endl;
		close(sock);
		return false;
	}

	string data="accept_request "+groupname+" "+username1+" "+username;
	TLSSendMsg(ssl,data);
	string output_str=TLSRecvMsg(ssl);
	TLSClose(ssl);
	size_t copy_len=output_str.size()<MAX_SIZE-1?output_str.size():MAX_SIZE-1;
	memcpy(output,output_str.c_str(),copy_len);
	output[copy_len]='\0';
	// cout<<output<<endl;

	close(sock);

	if(output[0]=='0')
		return false;
	else
		return true;
}

pair<string,long long int> GetFileHash(string filename){
	int max_limit=CHUNK_SIZE;
	
	unsigned char result[2*SHA_DIGEST_LENGTH+1];
	unsigned char hash[SHA_DIGEST_LENGTH];

	FILE *f = fopen(filename.c_str(),"rb");

	if(f==NULL){
		return make_pair("",0);
	}

	EVP_MD_CTX *mdContent=EVP_MD_CTX_new();
	unsigned char data[max_limit+1];
	int bytes;
	unsigned int hash_len;
	long long int file_size=0;
	string final_hash="";

	while((bytes=fread(data, 1, max_limit, f))){
		data[bytes]='\0';
		file_size+=bytes;

		EVP_DigestInit_ex(mdContent, EVP_sha1(), NULL);

		EVP_DigestUpdate(mdContent, data, bytes);
		EVP_DigestFinal_ex(mdContent, hash, &hash_len);
		for(int i=0; i < SHA_DIGEST_LENGTH;i++){
		  sprintf((char *)&(result[i*2]), "%02x",hash[i]);
		}
		// printf("%s\n",result);
		// cout<<bytes<<endl;
		string temp_hash(result,result+20);

		// cout<<temp_hash.size()<<endl;

		final_hash=final_hash+temp_hash;
	}

	EVP_MD_CTX_free(mdContent);
	fclose(f);

	return make_pair(final_hash,file_size);
}

bool FileUpload(pair<string,long long int> file_metadata,string groupname,string username,string filename,string path){
	struct sockaddr_in remote_server;
	int sock;
	char output[MAX_SIZE];

	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
		perror("socket");
		exit(-1);
	}

	remote_server.sin_family=AF_INET;
	remote_server.sin_port=htons(sp);
	remote_server.sin_addr.s_addr=inet_addr(si.c_str());
	bzero(&remote_server.sin_zero,8);

	if((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1){
		perror("connect");
		exit(-1);
	}

	SSL* ssl=TLSConnect(tracker_ctx,sock);
	if(!ssl){
		cerr<<"TLS handshake with tracker failed"<<endl;
		close(sock);
		return false;
	}

	string data="upload_file "+file_metadata.first+" "+to_string(file_metadata.second)+" "+groupname+" "+username+" "+filename+" "+path;

	// cout<<data<<" "<<data.size()<<endl;

	TLSSendMsg(ssl,data);
	string output_str=TLSRecvMsg(ssl);
	TLSClose(ssl);
	size_t copy_len=output_str.size()<MAX_SIZE-1?output_str.size():MAX_SIZE-1;
	memcpy(output,output_str.c_str(),copy_len);
	output[copy_len]='\0';
	// cout<<output<<endl;

	close(sock);

	if(output[0]=='0')
		return false;
	else
		return true;
}

bool GroupStopShare(string groupname,string filename,string username){
	struct sockaddr_in remote_server;
	int sock;
	char output[MAX_SIZE];

	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
		perror("socket");
		exit(-1);
	}

	remote_server.sin_family=AF_INET;
	remote_server.sin_port=htons(sp);
	remote_server.sin_addr.s_addr=inet_addr(si.c_str());
	bzero(&remote_server.sin_zero,8);

	if((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1){
		perror("connect");
		exit(-1);
	}

	SSL* ssl=TLSConnect(tracker_ctx,sock);
	if(!ssl){
		cerr<<"TLS handshake with tracker failed"<<endl;
		close(sock);
		return false;
	}

	string data="stop_share "+groupname+" "+filename+" "+username;
	TLSSendMsg(ssl,data);
	string output_str=TLSRecvMsg(ssl);
	TLSClose(ssl);
	size_t copy_len=output_str.size()<MAX_SIZE-1?output_str.size():MAX_SIZE-1;
	memcpy(output,output_str.c_str(),copy_len);
	output[copy_len]='\0';
	// cout<<output<<endl;

	close(sock);

	if(output[0]=='0')
		return false;
	else
		return true;
}

bool GroupLeave(string groupname,string username){
	struct sockaddr_in remote_server;
	int sock;
	char output[MAX_SIZE];

	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
		perror("socket");
		exit(-1);
	}

	remote_server.sin_family=AF_INET;
	remote_server.sin_port=htons(sp);
	remote_server.sin_addr.s_addr=inet_addr(si.c_str());
	bzero(&remote_server.sin_zero,8);

	if((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1){
		perror("connect");
		exit(-1);
	}

	SSL* ssl=TLSConnect(tracker_ctx,sock);
	if(!ssl){
		cerr<<"TLS handshake with tracker failed"<<endl;
		close(sock);
		return false;
	}

	string data="leave_group "+groupname+" "+username;
	TLSSendMsg(ssl,data);
	string output_str=TLSRecvMsg(ssl);
	TLSClose(ssl);
	size_t copy_len=output_str.size()<MAX_SIZE-1?output_str.size():MAX_SIZE-1;
	memcpy(output,output_str.c_str(),copy_len);
	output[copy_len]='\0';
	// cout<<output<<endl;

	close(sock);

	if(output[0]=='0')
		return false;
	else
		return true;
}

void ShowDownloads(string username){
	struct sockaddr_in remote_server;
	int sock;
	char output[MAX_SIZE];

	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
		perror("socket");
		exit(-1);
	}

	remote_server.sin_family=AF_INET;
	remote_server.sin_port=htons(sp);
	remote_server.sin_addr.s_addr=inet_addr(si.c_str());
	bzero(&remote_server.sin_zero,8);

	if((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1){
		perror("connect");
		exit(-1);
	}

	SSL* ssl=TLSConnect(tracker_ctx,sock);
	if(!ssl){
		cerr<<"TLS handshake with tracker failed"<<endl;
		close(sock);
		return;
	}

	string data="show_downloads "+username;
	TLSSendMsg(ssl,data);
	string output_str=TLSRecvMsg(ssl);
	TLSClose(ssl);
	size_t copy_len=output_str.size()<MAX_SIZE-1?output_str.size():MAX_SIZE-1;
	memcpy(output,output_str.c_str(),copy_len);
	output[copy_len]='\0';
	cout<<"##### List of Downloads #####"<<endl<<endl;
	cout<<output<<endl;

	cout<<"#####  #####"<<endl;

	close(sock);
}

bool Logout(string username){

	struct sockaddr_in remote_server;
	int sock;
	char output[MAX_SIZE];

	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
		perror("socket");
		exit(-1);
	}

	remote_server.sin_family=AF_INET;
	remote_server.sin_port=htons(sp);
	remote_server.sin_addr.s_addr=inet_addr(si.c_str());
	bzero(&remote_server.sin_zero,8);

	if((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1){
		perror("connect");
		exit(-1);
	}

	SSL* ssl=TLSConnect(tracker_ctx,sock);
	if(!ssl){
		cerr<<"TLS handshake with tracker failed"<<endl;
		close(sock);
		return false;
	}

	string data="logout "+username;
	TLSSendMsg(ssl,data);
	string output_str=TLSRecvMsg(ssl);
	TLSClose(ssl);
	size_t copy_len=output_str.size()<MAX_SIZE-1?output_str.size():MAX_SIZE-1;
	memcpy(output,output_str.c_str(),copy_len);
	output[copy_len]='\0';
	// cout<<output<<endl;

	close(sock);

	if(output[0]=='0')
		return false;
	else
		return true;
}

int main(int argc, char** argv){

	bool flag=true;
	bool login_flag=false;
	string command;
	pthread_t tid;
	vector<string> command_split(10);

	myip=argv[1];
	string myport=argv[2];
	int myport_i=atoi(myport.c_str());
	string filepath=argv[3];

	// Certs live in a "certs" directory alongside the tracker_info.txt file
	// (project root for a bare-metal run, /app for the Docker image) -
	// see certs/generate-dev-cert.sh.
	size_t last_slash=filepath.find_last_of('/');
	string certdir=(last_slash==string::npos) ? "certs" : filepath.substr(0,last_slash)+"/certs";

	TLSGlobalInit();
	tracker_ctx=TLSClientContext(certdir+"/tracker.crt");

	auto pid=pthread_create(&tid,NULL,ClientServer,&myport_i);

	if(pid!=0){
			perror("thread failed");
			exit(-1);
	}

	while(flag){
		command="";
		getline(cin,command);
		if(cin.eof()){
			// No interactive controlling terminal (e.g. started in the
			// background). Block here instead of busy-spinning on a
			// closed stdin, while ClientServer keeps serving chunks.
			pthread_join(tid,NULL);
			break;
		}
		stringstream command_object(command);
		command_object>>command_split[0];

		if(command_split[0]=="quit")
			break;

		if(!CheckTracker(filepath)){
			cout<<"No tracker online"<<endl;
			continue;
		}

		if(command_split[0]=="login"){
			if(login_flag){
				cout<<"Already Logged in"<<endl;
				continue;
			}
			command_object>>command_split[1];
			command_object>>command_split[2];

			login_flag=UserLogin(command_split[1],command_split[2],myport_i);
			if(login_flag){
				cout<<"Successful"<<endl;
				username=command_split[1];
			}
			else{
				cout<<"Failed"<<endl;
			}
		}
		else if(command_split[0]=="create_user"){
			if(login_flag){
				cout<<"Already Logged in"<<endl;
				continue;
			}

			command_object>>command_split[1];
			command_object>>command_split[2];
			login_flag=UserCreate(command_split[1],command_split[2],myport_i);

			if(login_flag){
				cout<<"Successful"<<endl;
				username=command_split[1];
			}
			else{
				cout<<"Failed"<<endl;
			}			
		}
		else if(command_split[0]=="create_group"){
			if(!login_flag){
				cout<<"Log in first"<<endl;
				continue;
			}

			command_object>>command_split[1];

			if(GroupCreate(command_split[1],username)){
				cout<<"Successful"<<endl;
			}
			else{
				cout<<"Failed"<<endl;
			}
		}
		else if(command_split[0]=="list_groups"){
			if(!login_flag){
				cout<<"Log in first"<<endl;
				continue;
			}
			GroupList();
		}
		else if(command_split[0]=="join_group"){
			if(!login_flag){
				cout<<"Log in first"<<endl;
				continue;
			}
			command_object>>command_split[1];

			if(!GroupJoin(command_split[1],username)){
				cout<<"Group Doesn't exists"<<endl;
			}
		}
		else if(command_split[0]=="list_requests"){
			if(!login_flag){
				cout<<"Log in first"<<endl;
				continue;
			}
			command_object>>command_split[1];

			GroupRequestList(command_split[1],username);
		}
		else if(command_split[0]=="accept_request"){
			if(!login_flag){
				cout<<"Log in first"<<endl;
				continue;
			}

			command_object>>command_split[1];
			command_object>>command_split[2];
			
			if(GroupAcceptRequest(command_split[1],command_split[2],username)){
				cout<<"Successful"<<endl;
			}
			else{
				cout<<"Invalid Request"<<endl;
			}			
		}
		else if(command_split[0]=="upload_file"){
			if(!login_flag){
				cout<<"Log in first"<<endl;
				continue;
			}

			command_object>>command_split[1];
			command_object>>command_split[2];

			auto file_metadata=GetFileHash(command_split[1]);

			if(file_metadata.first.size()==0){
				cout<<"Cannot open file"<<endl;
				continue;
			}

			auto names=split(command_split[1],'/');
			string name=names[names.size()-1];

			if(FileUpload(file_metadata,command_split[2],username,name,command_split[1])){
				cout<<"Successful"<<endl;
			}
			else{
				cout<<"Invalid Request"<<endl;
			}
			
		}
		else if(command_split[0]=="list_files"){
			if(!login_flag){
				cout<<"Log in first"<<endl;
				continue;
			}
			command_object>>command_split[1];

			GroupRequestFiles(command_split[1]);
		}
		else if(command_split[0]=="stop_share"){
			if(!login_flag){
				cout<<"Log in first"<<endl;
				continue;
			}

			command_object>>command_split[1];
			command_object>>command_split[2];
			
			if(GroupStopShare(command_split[1],command_split[2],username)){
				cout<<"Successful"<<endl;
			}
			else{
				cout<<"Invalid Request"<<endl;
			}			
		}
		else if(command_split[0]=="leave_group"){
			if(!login_flag){
				cout<<"Log in first"<<endl;
				continue;
			}

			command_object>>command_split[1];
			if(GroupLeave(command_split[1],username)){
				cout<<"Successful"<<endl;
			}
			else{
				cout<<"Invalid Request"<<endl;
			}	
		}
		else if(command_split[0]=="download_file"){
			if(!login_flag){
				cout<<"Log in first"<<endl;
				continue;
			}

			command_object>>command_split[1];
			command_object>>command_split[2];
			command_object>>command_split[3];

			DownloadFile(command_split[1],command_split[2],command_split[3],username,myip,si,sp,filepath);
		}
		else if(command_split[0]=="show_downloads"){
			if(!login_flag){
				cout<<"Log in first"<<endl;
				continue;
			}

			ShowDownloads(username);
		}
		else if(command_split[0]=="logout"){
			if(!login_flag){
				cout<<"Log in first"<<endl;
				continue;
			}

			if(Logout(username)){
				cout<<"Successful"<<endl;
				login_flag=false;
			}
			else{
				cout<<"Failed"<<endl;
			}
		}
		else{
			if(!login_flag){
				cout<<"Log in first"<<endl;
				continue;
			}
			cout<<"Invalid command"<<endl;
		}
		// cout<<"End"<<endl;
		cout<<endl;
	}

	return 0;
}