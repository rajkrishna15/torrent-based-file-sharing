#include "peerdownload.h"
#include "tls.h"

extern unordered_map<string,vector<int>> filechunks_map;
extern pthread_mutex_t filechunks_lock;
extern string RecvAll(int sock);
extern SSL_CTX* tracker_ctx;

struct FILEDATA{
	string name;
	string path;
	string hash;
	string size;
	string groupname;
	string serverpath;
	string username;
	string tracker_ip;
	int tracker_port;
	vector<string> seeders;
	unordered_map<string,pair<string,string> > details;
};

struct ChunkData
{
	struct FILEDATA* pointer;
	int chunk_num;
	int seeder_num;
};

bool my_comp(const pair<int,vector<int>> &a,const pair<int,vector<int>> &b){
	if(a.second.size()<=b.second.size())
		return true;
	return false;
}

void populate(vector<vector<int> > &matrix,vector<pair<int,vector<int> > > v){
	int count=0;
	for(auto i:v){
		matrix[count][0]=i.first;
		for(auto j:i.second){
			// cout<<i.first<<" "<<j<<endl;
			matrix[count][j]=1;
		}
		++count;
	}
}

void Decide(vector<vector<int> > matrix,vector<int> &chunks){
	int n=matrix.size();
	int m=matrix[0].size();

	// cout<<n<<" "<<m<<endl;

	for(int j=1;j<m;++j){
		for(int i=0;i<n;++i){
			if(matrix[i][j]!=-1){
				int x=j-1;
				// cout<<i<<" "<<j<<" "<<x<<endl;
				if(chunks[x]==-1){
					chunks[x]=matrix[i][0];
				}
			}
		}
	}
}

vector<string> split2(string data,char delim){
	vector<string> v;
	string temp="";
	for(long long unsigned int i=0;i<data.size();++i){
		if(data[i]==delim){
			v.push_back(temp);
			temp="";
		}
		else{
			// const char x=data[i];
			// cout<<x<<endl;
			temp.append(data,i,1);
			// cout<<temp<<endl;
		}
	}
	v.push_back(temp);

	return v;
}

void print(std::vector<int> v){
	cout<<"########"<<endl;
	for(auto i:v){
		cout<<i<<" ";
	}
	cout<<endl;
}

pair<bool,vector<int> > CalcChunk(long long int nchunks,struct FILEDATA *filemeta){
	vector <int> seeders_chunk(nchunks,-1);
	vector<vector<int> > matrix(filemeta->seeders.size(),vector<int> (nchunks+1,-1));
	vector<pair<int,vector<int> > > v;
	bool flag=false;

	for(unsigned int i=0;i<filemeta->seeders.size();++i){
		string conn_ip=filemeta->details[filemeta->seeders[i]].first;
		int conn_port=atoi((filemeta->details[filemeta->seeders[i]].second).c_str());

		struct sockaddr_in remote_server;
		int sock;

		if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
			perror("socket");
			exit(-1);
		}

		remote_server.sin_family=AF_INET;
		remote_server.sin_port=htons(conn_port);
		remote_server.sin_addr.s_addr=inet_addr(conn_ip.c_str());
		bzero(&remote_server.sin_zero,8);

		if((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1){
			perror("connect");
			exit(-1);
		}

		string data="chunk_numbers "+filemeta->name;
		send(sock,data.c_str(),data.size(),0);
		shutdown(sock,SHUT_WR);
		string output_string=RecvAll(sock);
		// cout<<i<<" "<<output_string<<endl;
		std::vector<int> temp;

		if(output_string=="-1"){
			for(int i=0;i<nchunks;++i)
				temp.push_back(i+1);

			v.push_back(make_pair(i,temp));
		}
		else if(output_string=="-2"){
			v.push_back(make_pair(i,temp));
			flag=true;
		}
		else{
			auto split_vector=split2(output_string,' ');
			for(auto x:split_vector)
				temp.push_back(atoi(x.c_str())+1);

			v.push_back(make_pair(i,temp));
			flag=true;
		}
	}
	sort(v.begin(),v.end(),my_comp);
	populate(matrix,v);
	Decide(matrix,seeders_chunk);
	// print(seeders_chunk);

	auto ret=make_pair(flag,seeders_chunk);

	return ret;

}

string ServerPath(string filename){
	string tracker_data="",line="";

	ifstream infile;
	infile.open(filename,ios::in);

	while(getline(infile,line)){
		// cout<<line<<endl;
		// stringstream line_object(line);
		// line_object>>temp_ip;
		// line_object>>temp_port;
		// tracker_info.push_back(make_pair(temp_ip,temp_port));
		auto split_vector_temp=split2(line,' ');
		tracker_data+=split_vector_temp[0]+" "+split_vector_temp[1]+" ";
	}
	tracker_data=tracker_data.substr(0,tracker_data.size()-1);
	return tracker_data;
}

// void GetChunks(struct FILEDATA* filemeta){
// 	for(auto i:filemeta->details){
// 		struct sockaddr_in remote_server;
// 		int sock;
// 		char output[MAX_SIZE1];

// 		if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
// 			perror("socket");
// 			exit(-1);
// 		}

// 		remote_server.sin_family=AF_INET;
// 		remote_server.sin_port=htons(atoi(i.second.second.c_str()));
// 		remote_server.sin_addr.s_addr=inet_addr(i.second.first.c_str());
// 		bzero(&remote_server.sin_zero,8);

// 		if((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1){
// 			perror("connect");
// 			exit(-1);
// 		}

// 		string data="Hello "+i.first;
// 		send(sock,data.c_str(),data.size(),0);
// 		int len=recv(sock,output,MAX_SIZE1,0);
// 		output[len]='\0';
// 		cout<<output<<endl;

// 		close(sock);
// 	}
// }

bool GetFileHashsmall(string filename,int nchunks,string fullhash){
	int max_limit=CHUNK_SIZE1;

	unsigned char result[2*SHA_DIGEST_LENGTH+1];
	unsigned char hash[SHA_DIGEST_LENGTH];

	FILE *f = fopen(filename.c_str(),"rb");
	long long int pos=nchunks*CHUNK_SIZE1;
	fseek(f,pos,SEEK_SET);

	// if(f==NULL){
	// 	return "";
	// }

	EVP_MD_CTX *mdContent=EVP_MD_CTX_new();
	unsigned char data[max_limit+1];
	int bytes;
	unsigned int hash_len;
	// long long int file_size=0;
	// string final_hash="";

	bytes=fread(data, 1, max_limit, f);
	data[bytes]='\0';
	// file_size+=bytes;

	EVP_DigestInit_ex(mdContent, EVP_sha1(), NULL);

	EVP_DigestUpdate(mdContent, data, bytes);
	EVP_DigestFinal_ex(mdContent, hash, &hash_len);
	for(int i=0; i < SHA_DIGEST_LENGTH;i++){
	  sprintf((char *)&(result[i*2]), "%02x",hash[i]);
	}
	// printf("%s\n",result);
	// cout<<bytes<<endl;
	string temp_hash(result,result+20);
	string x=fullhash.substr(nchunks*20,20);

	EVP_MD_CTX_free(mdContent);
	fclose(f);

	// cout<<temp_hash.size()<<endl;

	// final_hash=final_hash+temp_hash;

	// return final_hash;

	if(temp_hash==x)
		return true;
	else
		return false;
}


// void UpdateServer(struct FILEDATA* filemeta){
// 	auto split_vector=split2(filemeta->serverpath,' ');
// 	auto all_trackers=Conv2(split_vector);
// 	auto online_tracker=CheckTracker2(all_trackers);

// 	string data="add_file "+filemeta->groupname+" "+filemeta->name+" "+filemeta->path+" "+filemeta->username;

// 	struct sockaddr_in remote_server;
// 	int sock;

// 	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
// 		perror("socket");
// 		exit(-1);
// 	}

// 	remote_server.sin_family=AF_INET;
// 	remote_server.sin_port=htons(online_tracker.second);
// 	remote_server.sin_addr.s_addr=inet_addr(online_tracker.first.c_str());
// 	bzero(&remote_server.sin_zero,8);

// 	if((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1){
// 		perror("connect");
// 		exit(-1);
// 	}

// 	send(sock,data.c_str(),data.size(),0);
// 	close(sock);
// }

// Both notifications below deliberately reuse the tracker (tracker_ip/
// tracker_port) that this download session already picked for give_sha/
// give_seeders, instead of independently re-resolving one via CheckTracker2.
// Routing give_sha/add_file/complete through different trackers let their
// cross-tracker Sync pushes race each other and could leave stale
// downloading/downloaded bookkeeping behind.

void UpdateServer(struct ChunkData* chunkmeta){
	string data="add_file "+chunkmeta->pointer->groupname+" "+chunkmeta->pointer->name+" "+chunkmeta->pointer->path+" "+chunkmeta->pointer->username;

	// cout<<"Sending Update"<<endl;
	// cout<<data<<endl;

	struct sockaddr_in remote_server;
	int sock;

	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
		perror("socket");
		exit(-1);
	}

	remote_server.sin_family=AF_INET;
	remote_server.sin_port=htons(chunkmeta->pointer->tracker_port);
	remote_server.sin_addr.s_addr=inet_addr(chunkmeta->pointer->tracker_ip.c_str());
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

	TLSSendMsg(ssl,data);
	TLSClose(ssl);
	close(sock);
}

void UpdateServerComplete(struct FILEDATA* filemeta){
	string data="complete "+filemeta->groupname+" "+filemeta->name+" "+filemeta->path+" "+filemeta->username;

	struct sockaddr_in remote_server;
	int sock;

	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
		perror("socket");
		exit(-1);
	}

	remote_server.sin_family=AF_INET;
	remote_server.sin_port=htons(filemeta->tracker_port);
	remote_server.sin_addr.s_addr=inet_addr(filemeta->tracker_ip.c_str());
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

	TLSSendMsg(ssl,data);
	TLSClose(ssl);
	close(sock);
}

void* DownloadKernel(void* pointer){
	struct ChunkData* chunkmeta=(struct ChunkData *)pointer;
	int nseeders=chunkmeta->pointer->seeders.size();
	int attempts=0;

	while(true){
		int num=chunkmeta->seeder_num;
		auto seeders=chunkmeta->pointer->seeders;
		auto details=chunkmeta->pointer->details;
		string seeder_name=seeders[num];
		string conn_ip=details[seeders[num]].first;
		int conn_port=atoi((details[seeders[num]].second).c_str());

		struct sockaddr_in remote_server;
		int sock;
		char output[SMALL_CHUNK_SIZE1];

		if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
			perror("socket");
			exit(-1);
		}

		remote_server.sin_family=AF_INET;
		remote_server.sin_port=htons(conn_port);
		remote_server.sin_addr.s_addr=inet_addr(conn_ip.c_str());
		bzero(&remote_server.sin_zero,8);

		if((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1){
			close(sock);
			++attempts;
			if(attempts>=nseeders){
				cout<<"Chunk "<<chunkmeta->chunk_num<<": no reachable seeder, giving up"<<endl;
				return NULL;
			}
			chunkmeta->seeder_num=(num+1)%nseeders;
			continue;
		}

		string data="send_chunk "+chunkmeta->pointer->groupname+" "+chunkmeta->pointer->name+" "+to_string(chunkmeta->chunk_num)+" "+chunkmeta->pointer->serverpath+" "+seeder_name;
		send(sock,data.c_str(),data.size(),0);
		shutdown(sock,SHUT_WR);

		string filepath=chunkmeta->pointer->path;
		long long int pos=chunkmeta->chunk_num*CHUNK_SIZE1;
		long long int file_size=CHUNK_SIZE1,n;

		FILE * fs=fopen(filepath.c_str(),"rb+");
		fseek(fs,pos,SEEK_SET);

		while ((n=recv(sock,output,SMALL_CHUNK_SIZE1,0))>0&&file_size>0){
			fwrite(output,sizeof(char),n,fs);
			memset(output,'\0',SMALL_CHUNK_SIZE1);
			file_size = file_size-n;
		}

		fclose(fs);
		close(sock);

		if(chunkmeta->chunk_num==0){
			UpdateServer(chunkmeta);
		}

		if(!GetFileHashsmall(filepath,chunkmeta->chunk_num,chunkmeta->pointer->hash))
			continue;

		pthread_mutex_lock(&filechunks_lock);
		filechunks_map[chunkmeta->pointer->name].push_back(chunkmeta->chunk_num);
		pthread_mutex_unlock(&filechunks_lock);

		return NULL;
	}
}

void GetChunks(struct FILEDATA* filemeta){
	long long int nchunks1=atoi((filemeta->size).c_str()),x;
	// cout<<"No. of chunks are "<<nchunks1<<endl;
	// cout<<"No. of chunks are "<<CHUNK_SIZE1<<endl;
	long long int nchunks=nchunks1/CHUNK_SIZE1;
	if(nchunks1%CHUNK_SIZE1)
		++nchunks;
	// cout<<"No. of chunks are "<<nchunks<<endl;
	pthread_t tid[1000];
	struct ChunkData* chunkmetas[1000];
	int counter=0;
	int nseeder=filemeta->seeders.size();
	int ncounter=0;

	// The platform default stack size for a non-main thread can be too
	// small once OpenSSL's lazy init (dlopen, invoked from EVP_DigestInit_ex
	// on first use) runs on it - give each chunk thread a bit more headroom.
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, 1024*1024);


	vector<int>t;
	pthread_mutex_lock(&filechunks_lock);
	filechunks_map[filemeta->name]=t;
	pthread_mutex_unlock(&filechunks_lock);

	auto decide=CalcChunk(nchunks,filemeta);

	for(long long int i=0;i<nchunks;++i){
		// pthread_t tid;

		// if(i%2)
		// 	x=1;
		// else x=0;
		if(!decide.first){
			x=ncounter;
			++ncounter;
			ncounter=ncounter%nseeder;
		}
		else{
			x=decide.second[i];
		}

		struct ChunkData* chunkmeta=new ChunkData;
		chunkmeta->pointer=filemeta;
		chunkmeta->chunk_num=i;
		chunkmeta->seeder_num=x;
		chunkmetas[counter]=chunkmeta;

		// cout<<chunkmeta->chunk_num<<" "<<chunkmeta->seeder_num<<endl;

		int pid=pthread_create(&tid[counter],&attr,DownloadKernel,(void *)chunkmeta);
		if(pid!=0){
			perror("thread failed");
			exit(-1);
			// cout<<"This has failed"<<endl;
		}
		++counter;
		counter=counter%1000;

		if(counter>50){
			for(int j=0;j<counter;++j){
				pthread_join(tid[j],NULL);
				delete chunkmetas[j];
			}
			counter=0;
		}
	}

	for(long long int i=0;i<counter;++i){
		pthread_join(tid[i],NULL);
		delete chunkmetas[i];
	}

	pthread_attr_destroy(&attr);
}

string GetFileHash2(string filename){
	int max_limit=CHUNK_SIZE1;

	unsigned char result[2*SHA_DIGEST_LENGTH+1];
	unsigned char hash[SHA_DIGEST_LENGTH];

	FILE *f = fopen(filename.c_str(),"rb");

	if(f==NULL){
		return "";
	}

	EVP_MD_CTX *mdContent=EVP_MD_CTX_new();
	unsigned char data[max_limit+1];
	int bytes;
	unsigned int hash_len;
	// long long int file_size=0;
	string final_hash="";

	while((bytes=fread(data, 1, max_limit, f))){
		data[bytes]='\0';
		// file_size+=bytes;

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

	return final_hash;
}

void MatchSHA(struct FILEDATA *filemeta){
	string filepath=filemeta->path;
	string x=GetFileHash2(filepath);

	if(x==filemeta->hash)
		cout<<"Full file matched"<<endl;
	else
		cout<<"Not Matched"<<endl;

}

void DownloadFile(string groupname, string filename, string filepath,string username,string myip,string si,int sp,string serverpath){

	struct FILEDATA* filemeta=new FILEDATA;
	struct sockaddr_in remote_server;
	int sock;

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
		cout<<"TLS handshake with tracker failed"<<endl;
		close(sock);
		delete filemeta;
		return;
	}

	string data="give_sha "+groupname+" "+filename+" "+username;
	TLSSendMsg(ssl,data);
	string filehash=TLSRecvMsg(ssl);
	TLSClose(ssl);

	if(filehash.size()==0){
		cout<<"Invalid request"<<endl;
		close(sock);
		delete filemeta;
		return;
	}

	close(sock);

	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
		perror("socket");
		exit(-1);
	}

	if((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1){
		perror("connect");
		exit(-1);
	}

	ssl=TLSConnect(tracker_ctx,sock);
	if(!ssl){
		cout<<"TLS handshake with tracker failed"<<endl;
		close(sock);
		delete filemeta;
		return;
	}

	data="give_seeders "+groupname+" "+filename+" "+username;

	TLSSendMsg(ssl,data);
	string output_string=TLSRecvMsg(ssl);
	TLSClose(ssl);

	close(sock);

	if(output_string.size()==0){
		cout<<"No seeders available"<<endl;
		delete filemeta;
		return;
	}
	else{
		auto split_vector=split2(output_string,' ');
		// for(auto i:split_vector)
			// cout<<i<<endl;
		string size=split_vector[split_vector.size()-1];
		split_vector.erase(split_vector.end()-1);
		// cout<<size<<endl;

		unordered_map<string,pair<string,string> > details;

		for(auto i:split_vector){
			// cout<<i<<endl;

			if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
				perror("socket");
				exit(-1);
			}

			if((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1){
				perror("connect");
				exit(-1);
			}

			ssl=TLSConnect(tracker_ctx,sock);
			if(!ssl){
				cout<<"TLS handshake with tracker failed"<<endl;
				close(sock);
				continue;
			}

			data="give_details "+i;

			TLSSendMsg(ssl,data);
			string cred=TLSRecvMsg(ssl);
			TLSClose(ssl);

			close(sock);

			auto split_vector2=split2(cred,' ');

			details[i]=make_pair(split_vector2[0],split_vector2[1]);
		}

		// for(auto j:details)
			// cout<<j.first<<" "<<j.second.first<<" "<<j.second.second<<endl;

		filemeta->name=filename;
		filemeta->path=filepath;
		filemeta->hash=filehash;
		filemeta->size=size;
		filemeta->seeders=split_vector;
		filemeta->details=details;
		filemeta->groupname=groupname;
		filemeta->username=username;
		filemeta->serverpath=ServerPath(serverpath);
		filemeta->tracker_ip=si;
		filemeta->tracker_port=sp;

		ofstream outfile(filepath,ios::out);
		// cout<<atoi(size.c_str())<<endl;
		for(long long int i=0;i<atoi(size.c_str());++i)
			outfile.write("5",1);
	}

	GetChunks(filemeta);
	// UpdateServer(filemeta);
	UpdateServerComplete(filemeta);
	MatchSHA(filemeta);
	// close(sock);

	// for(auto ix:filechunks_map){
	// 	cout<<ix.first<<" ";
	// 	for(auto j:ix.second)
	// 		cout<<j<<" ";
	// 	cout<<endl;
	// }

	pthread_mutex_lock(&filechunks_lock);
	filechunks_map.erase(filemeta->name);
	pthread_mutex_unlock(&filechunks_lock);
	delete filemeta;
	return;
}