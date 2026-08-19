#include "peerserver.h"
#include "tls.h"

extern unordered_map<string,vector<int>> filechunks_map;
extern pthread_mutex_t filechunks_lock;
extern string RecvAll(int sock);
extern SSL_CTX* tracker_ctx;

struct Message{
	int new_cli;
	struct sockaddr_in client;
	string client_ip;
	string client_port;
};

string GetChunkInfo(string filename){
	string data="";

	pthread_mutex_lock(&filechunks_lock);
	auto find_itr=filechunks_map.find(filename);
	if(find_itr==filechunks_map.end()){
		pthread_mutex_unlock(&filechunks_lock);
		return "-1";
	}
	auto itr=find_itr->second;
	pthread_mutex_unlock(&filechunks_lock);

	if(itr.size()==0)
		return "-2";

	for(unsigned int i=0;i<itr.size();++i){
		data+=to_string(itr[i])+" ";
	}
	data=data.substr(0,data.size()-1);

	return data;
}

vector<string> split(string data,char delim){
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

pair<string,int> CheckTracker(vector<pair<string,int> > tracker_data){

	struct sockaddr_in remote_server;
	int sock;
	pair<string,int> server_final;

	for(auto i:tracker_data){
		// cout<<split_vector[0]<<endl;
		// cout<<split_vector[1]<<endl;

		if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
			perror("socket");
			// exit(-1);
		}

		remote_server.sin_family=AF_INET;
		remote_server.sin_port=htons(i.second);
		remote_server.sin_addr.s_addr=inet_addr(i.first.c_str());
		bzero(&remote_server.sin_zero,8);

		if(!((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1)){
			// perror("connect");
			// exit(-1);
			server_final=make_pair(i.first,i.second);
			// cout<<"Connected to "<<i.second<<endl;

			close(sock);

			return server_final;
		}
	}
	return server_final;
}

string GetFilePath(pair<string,int> server_final,string groupname,string filename,string username){
	struct sockaddr_in remote_server;
	int sock;
	char output[MAX_SIZE2];

	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
		perror("socket");
		exit(-1);
	}

	remote_server.sin_family=AF_INET;
	remote_server.sin_port=htons(server_final.second);
	remote_server.sin_addr.s_addr=inet_addr(server_final.first.c_str());
	bzero(&remote_server.sin_zero,8);

	if((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1){
		perror("connect");
		exit(-1);
	}

	SSL* ssl=TLSConnect(tracker_ctx,sock);
	if(!ssl){
		cerr<<"TLS handshake with tracker failed"<<endl;
		close(sock);
		return "";
	}

	string data="send_full_path "+username+" "+groupname+" "+filename;
	TLSSendMsg(ssl,data);
	string output_str=TLSRecvMsg(ssl);
	TLSClose(ssl);
	size_t copy_len=output_str.size()<MAX_SIZE2-1?output_str.size():MAX_SIZE2-1;
	memcpy(output,output_str.c_str(),copy_len);
	output[copy_len]='\0';

	close(sock);

	string full_path(output);

	// cout<<"full_path is "<<full_path<<endl;

	return full_path;
}

vector<pair<string,int> >Conv(vector<string> split_vector){
	vector<pair<string,int> >tracker_data;
	// int n=split_vector.size();

	// for(unsigned int k=0;k<split_vector.size();++k)
	// 	cout<<k<<" "<<split_vector[k]<<endl;

	tracker_data.push_back(make_pair(split_vector[4],atoi(split_vector[5].c_str())));
	tracker_data.push_back(make_pair(split_vector[6],atoi(split_vector[7].c_str())));

	// cout<<"tracker_data"<<endl;

	// for(auto i:tracker_data)
	// 	cout<<i.first<<" "<<i.second<<endl;

	return tracker_data;
}

void TransferFunction(vector<string> split_vector,struct Message* message){
	auto tracker_data=Conv(split_vector);
	auto server_final=CheckTracker(tracker_data);
	string full_path=GetFilePath(server_final,split_vector[1],split_vector[2],split_vector[8]);
	// cout<<full_path<<endl;
	long long int pos=atoi(split_vector[3].c_str())*CHUNK_SIZE2,total=0;
	int n;
	// bool flag=true;
	char data_file[SMALL_CHUNK_SIZE2];

	FILE *fs=fopen(full_path.c_str(),"rb");
	fseek(fs,pos,SEEK_SET);

	total=CHUNK_SIZE2+1;
	// cout<<"Start Pos "<<pos<<"End "<<total<<endl;

	while((n=fread(data_file,sizeof(char),SMALL_CHUNK_SIZE2,fs))>0&&(total>0)){
		send(message->new_cli,data_file, n,0);
		memset(data_file,'\0',SMALL_CHUNK_SIZE2);
		total=total-n ;

		// cout<<n<<" "<<total<<endl;
	}

	// cout<<"Start Pos "<<pos<<"End "<<total<<endl;	
}

void* ClientServerKernel(void* pointer){
	vector<string> command_split(10);
	struct Message* message=(struct Message *)pointer;

	string command=RecvAll(message->new_cli);
	stringstream command_object(command);
	command_object>>command_split[0];

	if(command_split[0]=="join_group"){
		command_object>>command_split[1];
		command_object>>command_split[2];

		// cout<<command_split[1]<<endl;
		// cout<<command_split[2]<<endl;
	}
	else if(command_split[0]=="Hello"){
		command_object>>command_split[1];
		// command_object>>command_split[2];

		// cout<<command_split[1]<<endl;
		string data="";

		send(message->new_cli,data.c_str(),data.size(),0);
	}
	else if(command_split[0]=="send_chunk"){
		// cout<<command<<endl;

		auto split_vector=split(command,' ');
		TransferFunction(split_vector,message);


	}
	else if(command_split[0]=="chunk_numbers"){
		// cout<<command<<endl;

		command_object>>command_split[1];

		string data=GetChunkInfo(command_split[1]);
		send(message->new_cli,data.c_str(),data.size(),0);
	}
	else{}

	close(message->new_cli);
	return NULL;
}


void* ClientServer(void* pointer){
	int my_port_i=*((int*)pointer);
	// cout<<"here"<<endl;
	// cout<<my_port_i<<endl;
	int counter=0;
	int lim=1000;
	int sock;
	int new_cli[lim];
	pthread_t tid[lim];
	// socklen_t len;


	struct sockaddr_in server;
	struct sockaddr_in client;
	int sockaddr_len=sizeof(struct sockaddr_in);

	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
		perror("server socket: ");
		exit(-1);
	}

	// Without this, a just-restarted peer can transiently fail to bind its
	// own port with EADDRINUSE while the OS finishes releasing the
	// previous listening socket.
	int reuse=1;
	setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));

	server.sin_family=AF_INET;
	server.sin_port=htons(my_port_i);
	server.sin_addr.s_addr=INADDR_ANY;
	bzero(&server.sin_zero,8);

	if((::bind(sock,(struct sockaddr*)&server,sockaddr_len))==-1){
		perror("Bind");
		exit(-1);
	}

	if(listen(sock,5)==-1){
		perror("Listen");
		exit(-1);
	}

	while(1){
		socklen_t len=sizeof(struct sockaddr_in);
		if((new_cli[counter]=accept(sock,(struct sockaddr*)&client,&len))==-1){
			perror("accept");
			exit(-1);
		}

		Message* message=new Message;
		message->new_cli=new_cli[counter];
		message->client=client;
		message->client_port=to_string(ntohs(client.sin_port));
		string temp(inet_ntoa(client.sin_addr));
		message->client_ip=temp;

		auto pid=pthread_create(&tid[counter],NULL,ClientServerKernel,(void *)message);
		if(pid!=0){
			perror("thread failed");
			exit(-1);
		}

		++counter;
		counter=counter%lim;

		if(counter>50){
			for(int j=0;j<counter;++j){
				pthread_join(tid[j],NULL);
			}
			counter=0;
		}
	}
}