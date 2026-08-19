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
#include <pthread.h>
#include <dirent.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "tls.h"
#include "trackersync.h"

#define MAX_SIZE 65535

using namespace std;

unordered_map<string,string> credentials;
unordered_map<string,pair<string,string> >online_users;
set<string> online;
set<string>group_members;
unordered_map<string,string> groups;
vector<pair<string,string>> tracker_info;
set<pair<string,string> > pending_group_requests;

pthread_mutex_t file_lock;
pthread_mutex_t global_lock;

// server_ctx presents this tracker's identity to incoming connections
// (from peers and from the sibling tracker). client_ctx is used when this
// tracker connects out to its sibling for Sync - both trackers share the
// same cert, so client_ctx trusts that one cert directly.
SSL_CTX* server_ctx;
SSL_CTX* client_ctx;

struct Message{
	int new_cli;
	struct sockaddr_in client;
	string client_ip;
	string client_port;
};

int mysequence_i;

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

string GenerateSalt(){
	unsigned char salt[16];
	RAND_bytes(salt,sizeof(salt));

	char hex[2*sizeof(salt)+1];
	for(unsigned int i=0;i<sizeof(salt);++i){
		sprintf(hex+i*2,"%02x",salt[i]);
	}
	hex[2*sizeof(salt)]='\0';

	return string(hex);
}

// Salted SHA-256, so a leaked .credential.txt doesn't hand out plaintext
// passwords (or let two users with the same password share a hash).
string HashPassword(string salt,string password){
	string salted=salt+password;
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hash_len;

	EVP_MD_CTX *mdContent=EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdContent,EVP_sha256(),NULL);
	EVP_DigestUpdate(mdContent,salted.c_str(),salted.size());
	EVP_DigestFinal_ex(mdContent,hash,&hash_len);
	EVP_MD_CTX_free(mdContent);

	char hex[2*EVP_MAX_MD_SIZE+1];
	for(unsigned int i=0;i<hash_len;++i){
		sprintf(hex+i*2,"%02x",hash[i]);
	}
	hex[2*hash_len]='\0';

	return string(hex);
}

void DeleteLine(string filename,string data,int index){
	string line;

	pthread_mutex_lock(&file_lock);

	ifstream infile(filename,ios::in);
	ofstream outfile(".all_files/.temp.txt",ios::out|ios::app);

	while(getline(infile,line)){
			vector<string> v=split(line,' ');
			if(v[index]==data)
				continue;
			else{
				outfile<<line<<endl;
			}
	}

	remove(filename.c_str());
	rename(".all_files/.temp.txt",filename.c_str());
	infile.close();
	outfile.close();

	pthread_mutex_unlock(&file_lock);
}

void DeleteLine(string filename,string data){
	string line;
	pthread_mutex_lock(&file_lock);

	ifstream infile(filename,ios::in);
	// cout<<"Whole line "<<data<<endl;
	ofstream outfile(".all_files/.temp.txt",ios::out|ios::app);

	while(getline(infile,line)){
			if(line==data)
				continue;
			else{
				// cout<<line<<endl;
				outfile<<line<<endl;
			}
	}

	remove(filename.c_str());
	rename(".all_files/.temp.txt",filename.c_str());
	infile.close();

	pthread_mutex_unlock(&file_lock);
}

bool CheckGroupFiles(string filehash,string filename,string username){
	ifstream infile(filename,ios::in);
	string line;

	pthread_mutex_lock(&file_lock);

	while(getline(infile,line)){
		auto file_vector=split(line,' ');
		if(file_vector[0]==filehash && file_vector[2]==username){
			// cout<<filehash<<" "<<username<<endl;
			// cout<<file_vector[0]<<" "<<file_vector[2]<<endl;
			pthread_mutex_unlock(&file_lock);
			return true;
		}
	}
	pthread_mutex_unlock(&file_lock);
	return false;
}

string GetGroupFileName(string filehash,string filename){
	pthread_mutex_lock(&file_lock);
	ifstream infile(filename,ios::in);
	string line;
	string name="";

	while(getline(infile,line)){
		auto file_vector=split(line,' ');
		if(file_vector[0]==filehash){
			name=file_vector[3];
			break;
		}
	}

	pthread_mutex_unlock(&file_lock);

	return name;
}

bool CheckIntegrity(string filehash,string filename,string upload_file){
	pthread_mutex_lock(&file_lock);
	ifstream infile(filename,ios::in);
	string line;

	while(getline(infile,line)){
		auto file_vector=split(line,' ');
		// cout<<line<<endl;
		if(file_vector[0]!=filehash && file_vector[3]==upload_file){
			pthread_mutex_unlock(&file_lock);
			return true;
		}
	}
	pthread_mutex_unlock(&file_lock);
	return false;
}

void CheckDir(){
	string s=".all_files";

	// struct dirent *entry=NULL;
	DIR *dp=NULL;

	dp=opendir(s.c_str());

	if(dp!=NULL){
		// cout<<"Open"<<endl;

		// while((entry=readdir(dp)))
		// 	cout<<entry->d_name<<endl;
		closedir(dp);
		return;
	}
	else{
		// cout<<"cannot"<<endl;
		mkdir(s.c_str(),0777);
	}

	return;
}

void FetchDetails(){
	credentials.clear();
	online.clear();
	online_users.clear();
	groups.clear();
	pending_group_requests.clear();
	string line,line1,line2;

	CheckDir();
	
	pthread_mutex_lock(&file_lock);
	ifstream infile(".all_files/.credential.txt",ios::in);
	if(infile){
		while(getline(infile,line)){
			stringstream line_object(line);
			line_object>>line1;
			line_object>>line2;

			credentials[line1]=line2;
		}
		infile.close();
	}
	else{
		infile.close();
		ofstream outfile(".all_files/.credential.txt",ios::out);
		outfile.close();
	}

	infile.open(".all_files/.online.txt",ios::in);
	if(infile){
		while(getline(infile,line)){
			vector<string> split_vector=split(line,' ');
			online.insert(split_vector[0]);
			online_users[split_vector[0] ]=make_pair(split_vector[1],split_vector[2]);
		}
		infile.close();
	}
	else{
		infile.close();
		ofstream outfile(".all_files/.online.txt",ios::out);
		outfile.close();
	}

	infile.open(".all_files/.group.txt",ios::in);
	if(infile){
		while(getline(infile,line)){
			vector<string> split_vector=split(line,' ');
			groups[split_vector[0] ]=split_vector[1];
		}
		infile.close();
	}
	else{
		infile.close();
		ofstream outfile(".all_files/.group.txt",ios::out);
		outfile.close();
	}

	infile.open(".all_files/.pending.txt",ios::in);
	if(infile){
		while(getline(infile,line)){
			stringstream line_object(line);
			line_object>>line1;
			line_object>>line2;

			pending_group_requests.insert(make_pair(line1,line2));
		}
		infile.close();
	}
	else{
		infile.close();
		ofstream outfile(".all_files/.pending.txt",ios::out);
		outfile.close();
	}
	pthread_mutex_unlock(&file_lock);
}

void FetchGroupMembers(string group_name){
	pthread_mutex_lock(&file_lock);
	string name=".all_files/.group_"+group_name+".txt";
	string line;
	group_members.clear();
	ifstream infile(name,ios::in);
	// cout<<name<<endl;
	while(getline(infile,line)){
		// cout<<line<<endl;
		group_members.insert(line);
	}
	pthread_mutex_unlock(&file_lock);
}

void SendMessage(string ip,string port,string data){
	struct sockaddr_in remote_server;
	int sock;

	// cout<<ip<<endl;
	// cout<<port<<endl;
	// cout<<data<<endl;

	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
		perror("socket");
		exit(-1);
	}

	remote_server.sin_family=AF_INET;
	remote_server.sin_port=htons(atoi(port.c_str()));
	remote_server.sin_addr.s_addr=inet_addr(ip.c_str());
	bzero(&remote_server.sin_zero,8);

	if((connect(sock,(struct sockaddr*)&remote_server,sizeof(struct sockaddr_in)))==-1){
		perror("connect");
		exit(-1);
	}

	send(sock,data.c_str(),data.size(),0);
	close(sock);
}

bool UserLogin(int new_cli,string command1,string command2,string command3,string command4,struct Message* message){

	FetchDetails();

	if(credentials.find(command1)==credentials.end()){
		return false;
	}
	else{
		string stored=credentials[command1];
		auto sep=stored.find(':');
		string salt=stored.substr(0,sep);
		string stored_hash=stored.substr(sep+1);

		if(HashPassword(salt,command2)==stored_hash){

			if(online.find(command1)==online.end()){
				online.insert(command1);

				pthread_mutex_lock(&file_lock);

				ofstream outfile(".all_files/.online.txt",ios::out|ios::app);
				outfile<<command1<<" ";
				outfile<<command4<<" ";
				outfile<<command3;
				outfile<<endl;

				pthread_mutex_unlock(&file_lock);

				Sync(".all_files/.online.txt",mysequence_i,tracker_info);
			}
			return true;

		}
		else{
			// pthread_mutex_unlock(&file_lock);
			return false;
		}
	}
}

bool UserCreate(int new_cli,string command1,string command2,string command3,string command4,struct Message* message){

	FetchDetails();

	if(credentials.find(command1)==credentials.end()){
		// online.insert(command1,make_pair(to_string()));
		pthread_mutex_lock(&file_lock);
		online.insert(command1);
		ofstream outfile(".all_files/.online.txt",ios::out|ios::app);
		outfile<<command1<<" ";
		outfile<<command4<<" ";
		outfile<<command3;
		outfile<<endl;

		ofstream outfile2(".all_files/.credential.txt",ios::out|ios::app);
		// if(outfile2){
		// 	cout<<"open"<<endl;
		// }
		// else
		// 	cout<<"Not open"<<endl;
		string salt=GenerateSalt();
		outfile2<<command1;
		outfile2<<" ";
		outfile2<<salt<<":"<<HashPassword(salt,command2);
		outfile2<<endl;
		outfile.close();

		string name=".all_files/.files_"+command1+".txt";
		ofstream outfile3(name,ios::out);
		outfile3.close();

		string name1=".all_files/.files_"+command1+"_downloading.txt";
		ofstream outfile4(name1,ios::out);
		outfile4.close();

		string name2=".all_files/.files_"+command1+"_downloaded.txt";
		ofstream outfile5(name2,ios::out);
		outfile5.close();

		pthread_mutex_unlock(&file_lock);

		Sync(".all_files/.online.txt",mysequence_i,tracker_info);
		Sync(".all_files/.credential.txt",mysequence_i,tracker_info);
		Sync(name,mysequence_i,tracker_info);
		Sync(name1,mysequence_i,tracker_info);
		Sync(name2,mysequence_i,tracker_info);

		FetchDetails();

		return true;
	}
	else{
		return false;
	}
}

bool GroupCreate(int new_cli,string command1,string command2,struct Message* message){

	FetchDetails();

	if(groups.find(command1)==groups.end()){
		// online.insert(command1,make_pair(to_string()));

		pthread_mutex_lock(&file_lock);

		ofstream outfile(".all_files/.group.txt",ios::out|ios::app);
		outfile<<command1;
		outfile<<" ";
		outfile<<command2;
		outfile<<endl;
		outfile.close();

		string name=".all_files/.group_"+command1+".txt";
		outfile.open(name,ios::out);
		outfile<<command2;
		outfile<<endl;
		outfile.close();

		string name1=".all_files/.group_"+command1+"_files.txt";
		outfile.open(name1,ios::out);
		outfile.close();

		pthread_mutex_unlock(&file_lock);

		Sync(".all_files/.group.txt",mysequence_i,tracker_info);
		Sync(name,mysequence_i,tracker_info);
		Sync(name1,mysequence_i,tracker_info);

		FetchDetails();

		return true;
	}
	else{
		return false;
	}
}

string GroupList(int new_cli,struct Message* message){

	FetchDetails();
	string data="";

	for(auto i:groups){
		data=data+i.first+'\n';
		// cout<<i.first<<" "<<i.second<<endl;
	}

	return data;
}

string GroupRequestList(int new_cli,struct Message* message,string command1,string command2){

	FetchDetails();
	string data="";

	auto iter=groups.find(command1);

	if(iter==groups.end() || command2!=iter->second)
		return data;
	else{
		for(auto i:pending_group_requests){
			// cout<<i.first<<" "<<i.second<<endl;
			if(i.second==command1){
				data=data+i.first+'\n';
			}
		}
	}

	return data;
}

string GroupFileList(int new_cli,struct Message* message,string command1){

	FetchDetails();
	string data="";

	auto iter=groups.find(command1);

	if(iter==groups.end())
		return data;
	else{

		set<string> files;
		string name=".all_files/.group_"+command1+"_files.txt";
		string line;

		pthread_mutex_lock(&file_lock);

		ifstream infile(name,ios::in);

		while(getline(infile,line)){
			auto split_vector=split(line,' ');
			files.insert(split_vector[3]);
		}

		infile.close();
		pthread_mutex_unlock(&file_lock);

		for(auto i:files){
			data=data+i+'\n';
		}
	}

	return data;
}

bool GroupJoin(int new_cli,string command1,string command2,struct Message* message){
	auto iter=groups.find(command1);

	if(iter==groups.end())
		return false;
	// cout<<"Output "<<command1<<" "<<command2<<" "<<iter->first<<" "<<iter->second<<endl;
	FetchGroupMembers(command1);
	if(group_members.find(command2)!=group_members.end()){
		cout<<"Already Memeber"<<endl;
		return true;
	}

	auto iter2=online.find(iter->second);
	if(iter2==online.end()){
		if(pending_group_requests.find(make_pair(command2,command1))==pending_group_requests.end()){
			pthread_mutex_lock(&file_lock);
			ofstream outfile(".all_files/.pending.txt",ios::out|ios::app);
			outfile<<command2<<" "<<command1<<endl;
			outfile.close();
			pending_group_requests.insert(make_pair(command2,command1));

			pthread_mutex_unlock(&file_lock);
		}
	}
	else{
		auto iter3=online_users[*iter2];
		// cout<<iter3.first<<" "<<iter3.second<<endl;

		pthread_mutex_lock(&file_lock);

		ofstream outfile(".all_files/.pending.txt",ios::out|ios::app);
		outfile<<command2<<" "<<command1<<endl;
		outfile.close();
		pthread_mutex_unlock(&file_lock);
		pending_group_requests.insert(make_pair(command2,command1));

		// string data="join_group "+command1+" "+command2;
		// cout<<"2nd"<<endl;
		// SendMessage(iter3.first,iter3.second,data);

		// Sync(".pending.txt");
	}

	Sync(".all_files/.pending.txt",mysequence_i,tracker_info);
	return true;
}

bool GroupAcceptRequest(int new_cli,string command1,string command2,string command3,struct Message* message){
	auto iter=groups.find(command1);
	auto iter1=credentials.find(command2);
	auto iter2=pending_group_requests.find(make_pair(command2,command1));
	// cout<<"group accept"<<endl;

	if(iter==groups.end() || iter->second != command3 || iter1==credentials.end() || iter2==pending_group_requests.end())
		return false;

	FetchGroupMembers(command1);
	if(group_members.find(command2)!=group_members.end()){
		// cout<<"Already Memeber"<<endl;
		return true;
	}
	string name=".all_files/.group_"+command1+".txt";
	string remove_line=command2+" "+command1;
	// cout<<name<<endl;

	pthread_mutex_lock(&file_lock);
	ofstream outfile(name,ios::out|ios::app);
	outfile<<command2<<endl;
	outfile.close();
	pthread_mutex_unlock(&file_lock);

	DeleteLine(".all_files/.pending.txt",remove_line);

	Sync(".all_files/.pending.txt",mysequence_i,tracker_info);
	Sync(name,mysequence_i,tracker_info);

	return true;
}

bool GroupFileUpload(int new_cli,string command1,string command2,string command3,string command4,string command5,string command6,struct Message* message){
	auto iter=groups.find(command3);

	// cout<<command1<<" "<<command2<<" "<<command3<<" "<<command4<<" "<<command5<<" "<<command6<<endl;


	if(iter==groups.end())
		return false;
	
	FetchGroupMembers(command3);
	if(group_members.find(command4)==group_members.end())
		return false;
	string name=".all_files/.group_"+command3+"_files.txt";

	if(CheckGroupFiles(command1,name,command4))
		return true;

	string file_name=GetGroupFileName(command1,name);
	if(file_name.size()>0)
		command5=file_name;

	if(CheckIntegrity(command1,name,command5))
		return false;

	pthread_mutex_lock(&file_lock);

	ofstream outfile(name,ios::out|ios::app);
	outfile<<command1<<" "<<command2<<" "<<command4<<" "<<command5<<endl;
	
	string name2=".all_files/.files_"+command4+".txt";
	ofstream outfile2(name2,ios::out|ios::app);
	outfile2<<command3<<" "<<command5<<" "<<command6<<endl;

	pthread_mutex_unlock(&file_lock);

	Sync(name,mysequence_i,tracker_info);
	Sync(name2,mysequence_i,tracker_info);

	return true;
}

bool GroupStopShare(int new_cli,string command1,string command2,string command3,struct Message* message){
	auto iter=groups.find(command1);
	auto iter1=credentials.find(command3);

	// cout<<command1<<" "<<command2<<" "<<command3<<endl;

	if(iter==groups.end() || iter1==credentials.end())
		return false;

	// cout<<command1<<" "<<command2<<" "<<command3<<endl;
	FetchGroupMembers(command1);
	if(group_members.find(command3)==group_members.end()){
		return false;
	}

	// cout<<command1<<" "<<command2<<" "<<command3<<endl;
	string name=".all_files/.group_"+command1+"_files.txt";
	string name1=".all_files/.files_"+command3+".txt";

	pthread_mutex_lock(&file_lock);

	ifstream infile(name,ios::in);
	ofstream outfile(".all_files/.temp.txt",ios::out);
	string line;

	while(getline(infile,line)){
		auto split_vector=split(line,' ');
		if(split_vector[3]==command2 && split_vector[2]==command3)
			continue;
		outfile<<line<<endl;
	}

	remove(name.c_str());
	rename(".all_files/.temp.txt",name.c_str());
	infile.close();
	outfile.close();

	// DeleteLine(name1,command2,1);

	ifstream infile2(name1,ios::in);
	ofstream outfile2(".all_files/.temp.txt",ios::out);

	while(getline(infile2,line)){
		auto split_vector=split(line,' ');
		if(split_vector[0]==command1 && split_vector[1]==command2)
			continue;
		outfile2<<line<<endl;
	}

	remove(name1.c_str());
	rename(".all_files/.temp.txt",name1.c_str());
	infile2.close();
	outfile2.close();

	pthread_mutex_unlock(&file_lock);

	Sync(name,mysequence_i,tracker_info);
	Sync(name1,mysequence_i,tracker_info);

	return true;
}

bool GroupLeave(int new_cli,string command1,string command2,struct Message* message){
	auto iter=groups.find(command1);

	// cout<<command1<<" "<<command2<<endl;

	if(iter==groups.end())
		return false;

	// cout<<command1<<" "<<command2<<" "<<iter->second<<endl;

	FetchGroupMembers(command1);
	if(group_members.find(command2)==group_members.end() || iter->second==command2){
		return false;
	}

	// cout<<command1<<" "<<command2<<endl;
	
	string name1=".all_files/.group_"+command1+".txt";
	string name2=".all_files/.group_"+command1+"_files.txt";
	string name3=".all_files/.files_"+command2+".txt";

	DeleteLine(name1,command2,0);
	DeleteLine(name2,command2,2);
	DeleteLine(name3,command1,0);

	Sync(name1,mysequence_i,tracker_info);
	Sync(name2,mysequence_i,tracker_info);
	Sync(name3,mysequence_i,tracker_info);

	FetchDetails();

	return true;
}

string SendSHA(int new_cli,struct Message* message,string command1,string command2,string command3){

	FetchDetails();
	string data="";

	auto iter=groups.find(command1);

	if(iter==groups.end())
		return data;
	else{

		set<string> files;
		unordered_map<string,string> file_hash;
		string name=".all_files/.group_"+command1+"_files.txt";
		string line;

		FetchGroupMembers(command1);
		if(group_members.find(command3)==group_members.end())
			return data;

		pthread_mutex_lock(&file_lock);

		ifstream infile(name,ios::in);

		while(getline(infile,line)){
			auto split_vector=split(line,' ');
			files.insert(split_vector[3]);
			file_hash.insert(make_pair(split_vector[3],split_vector[0]));
		}

		infile.close();

		name=".all_files/.files_"+command3+"_downloading.txt";
		ofstream outfile(name,ios::app);
		outfile<<command1<<" "<<command2<<endl;
		outfile.close();

		pthread_mutex_unlock(&file_lock);

		Sync(name,mysequence_i,tracker_info);

		if(files.find(command2)==files.end())
			return data;

		data=file_hash[command2];
	}

	return data;
}

string SendSeeders(int new_cli,struct Message* message,string command1,string command2,string command3){

	FetchDetails();
	string data="";
	string size;

	set<string> seeders;
	string name=".all_files/.group_"+command1+"_files.txt";
	string line;

	pthread_mutex_lock(&file_lock);

	ifstream infile(name,ios::in);

	while(getline(infile,line)){
		auto split_vector=split(line,' ');
		
		if(split_vector[3]==command2){
			size=split_vector[1];
			if(online.find(split_vector[2])!=online.end())
				seeders.insert(split_vector[2]);
		}
	}

	infile.close();
	pthread_mutex_unlock(&file_lock);

	for(auto i:seeders)
		data+=i+" ";

	if(data.size()>0)
		data+=size;

	return data;
}

string SendDetails(int new_cli,struct Message* message,string command1){
	FetchDetails();
	string data="";

	auto itr=online_users[command1];

	data+=itr.first+" "+itr.second;

	return data;
}

string GetFullPath(int new_cli,struct Message* message,string command1,string command2,string command3){

	// FetchDetails();
	string data="";
	string size;

	set<string> seeders;
	string name=".all_files/.files_"+command1+".txt";
	string line;

	// pthread_mutex_lock(&file_lock);

	ifstream infile(name,ios::in);

	while(getline(infile,line)){
		auto split_vector=split(line,' ');
		
		if(split_vector[0]==command2 && split_vector[1]==command3){
			data=split_vector[2];
			break;
		}
	}

	infile.close();
	// pthread_mutex_unlock(&file_lock);

	return data;
}

void UpdateDownload(int new_cli,struct Message* message,string command1,string command2,string command3,string command4){

	FetchDetails();
	// cout<<"Updating "<<endl;
	string data="";
	string size;

	set<string> seeders;
	string name=".all_files/.group_"+command1+"_files.txt";
	string name2=".all_files/.files_"+command4+".txt";
	string line;

	// cout<<name<<" "<<name2<<endl;

	// pthread_mutex_lock(&file_lock);

	ifstream infile(name,ios::in);

	while(getline(infile,line)){
		auto split_vector=split(line,' ');

		// cout<<line<<endl;
		// cout<<command2<<endl;
		
		if(split_vector[3]==command2){
			data=split_vector[0];
			size=split_vector[1];
			break;
		}
	}

	infile.close();

	ifstream infile1(name2,ios::in);

	while(getline(infile1,line)){
		auto split_vector=split(line,' ');
		
		if(split_vector[1]==command2){
			infile1.close();
			pthread_mutex_unlock(&file_lock);
			return;
		}
	}

	infile1.close();

	ofstream outfile(name2,ios::out|ios::app);
	outfile<<command1<<" "<<command2<<" "<<command3<<endl;
	outfile.close();

	ofstream outfile1(name,ios::out|ios::app);
	outfile1<<data<<" "<<size<<" "<<command4<<" "<<command2<<endl;
	outfile1.close();

	Sync(name,mysequence_i,tracker_info);
	Sync(name2,mysequence_i,tracker_info);

	// pthread_mutex_unlock(&file_lock);
}

string ShowDownloads(int new_cli,struct Message* message,string command1){

	FetchDetails();
	string data="";
	
	string name=".all_files/.files_"+command1+"_downloading.txt";
	string name1=".all_files/.files_"+command1+"_downloaded.txt";
	string line;

	pthread_mutex_lock(&file_lock);

	ifstream infile(name,ios::in);

	while(getline(infile,line)){
		data+="[D] "+line+'\n';
	}

	infile.close();

	ifstream infile1(name1,ios::in);

	while(getline(infile1,line)){
		data+="[C] "+line+'\n';
	}

	infile1.close();

	pthread_mutex_unlock(&file_lock);

	return data;
}

void CompleteDownload(int new_cli,struct Message* message,string command1,string command2,string command3,string command4){

	FetchDetails();
	// cout<<"Completing "<<endl;
	string data="";
	string size;

	set<string> seeders;
	string name=".all_files/.files_"+command4+"_downloaded.txt";
	string name2=".all_files/.files_"+command4+"_downloading.txt";
	string target=command1+" "+command2;
	string line;

	// cout<<"Target "<<name2<<" "<<target<<endl;

	DeleteLine(name2,target);

	// pthread_mutex_lock(&file_lock);

	ofstream outfile(name,ios::out|ios::app);
	outfile<<target<<endl;
	outfile.close();

	Sync(name,mysequence_i,tracker_info);
	Sync(name2,mysequence_i,tracker_info);

	// pthread_mutex_unlock(&file_lock);
}

bool Logout(string command1){

	FetchDetails();

	if(online.find(command1)!=online.end()){
		// online.insert(command1,make_pair(to_string()));

		DeleteLine(".all_files/.online.txt",command1,0);
		Sync(".all_files/.online.txt",mysequence_i,tracker_info);

		FetchDetails();

		return true;
	}
	else{
		return false;
	}
}

void *TrackerKernel(void *pointer){
	vector<string> command_split(10);
	struct Message* message=(struct Message *)pointer;

	SSL* ssl=TLSAccept(server_ctx,message->new_cli);
	if(!ssl){
		close(message->new_cli);
		return NULL;
	}

	// A single length-prefixed TLSRecvMsg for dispatch, not "read until
	// close": the "Sync"/"SyncAll" commands reuse this same connection
	// afterward for their own multi-round-trip lockstep exchange
	// (SyncRecv), so reading until the peer closes the connection would
	// swallow that whole exchange instead of just this dispatch line.
	string command=TLSRecvMsg(ssl);
	stringstream command_object(command);
	command_object>>command_split[0];

	if(command_split[0]=="login"){
		command_object>>command_split[1];
		command_object>>command_split[2];
		command_object>>command_split[3];
		command_object>>command_split[4];

		if(UserLogin(message->new_cli,command_split[1],command_split[2],command_split[3],command_split[4],message)){
			TLSSendMsg(ssl,"1");
		}
		else
			TLSSendMsg(ssl,"0");
	}
	else if(command_split[0]=="create_user"){
		command_object>>command_split[1];
		command_object>>command_split[2];
		command_object>>command_split[3];
		command_object>>command_split[4];

		if(UserCreate(message->new_cli,command_split[1],command_split[2],command_split[3],command_split[4],message)){
			TLSSendMsg(ssl,"1");
		}
		else
			TLSSendMsg(ssl,"0");
	}
	else if(command_split[0]=="create_group"){
		command_object>>command_split[1];
		command_object>>command_split[2];

		if(GroupCreate(message->new_cli,command_split[1],command_split[2],message)){
			TLSSendMsg(ssl,"1");
		}
		else
			TLSSendMsg(ssl,"0");
	}
	else if(command_split[0]=="list_groups"){
		string data=GroupList(message->new_cli,message);
		TLSSendMsg(ssl,data);
	}
	else if(command_split[0]=="join_group"){
		command_object>>command_split[1];
		command_object>>command_split[2];

		if(GroupJoin(message->new_cli,command_split[1],command_split[2],message)){
			TLSSendMsg(ssl,"1");
		}
		else
			TLSSendMsg(ssl,"0");
	}
	else if(command_split[0]=="list_requests"){
		command_object>>command_split[1];
		command_object>>command_split[2];

		string data=GroupRequestList(message->new_cli,message,command_split[1],command_split[2]);
		TLSSendMsg(ssl,data);
	}
	else if(command_split[0]=="accept_request"){
		command_object>>command_split[1];
		command_object>>command_split[2];
		command_object>>command_split[3];

		if(GroupAcceptRequest(message->new_cli,command_split[1],command_split[2],command_split[3],message)){
			TLSSendMsg(ssl,"1");
		}
		else
			TLSSendMsg(ssl,"0");
	}
	else if(command_split[0]=="upload_file"){
		command_object>>command_split[1];
		command_object>>command_split[2];
		command_object>>command_split[3];
		command_object>>command_split[4];
		command_object>>command_split[5];
		command_object>>command_split[6];

		if(GroupFileUpload(message->new_cli,command_split[1],command_split[2],command_split[3],command_split[4],command_split[5],command_split[6],message)){
			TLSSendMsg(ssl,"1");
		}
		else
			TLSSendMsg(ssl,"0");
	}
	else if(command_split[0]=="list_files"){
		command_object>>command_split[1];

		string data=GroupFileList(message->new_cli,message,command_split[1]);
		TLSSendMsg(ssl,data);
	}
	else if(command_split[0]=="stop_share"){
		command_object>>command_split[1];
		command_object>>command_split[2];
		command_object>>command_split[3];

		if(GroupStopShare(message->new_cli,command_split[1],command_split[2],command_split[3],message)){
			TLSSendMsg(ssl,"1");
		}
		else
			TLSSendMsg(ssl,"0");
	}
	else if(command_split[0]=="leave_group"){
		command_object>>command_split[1];
		command_object>>command_split[2];

		if(GroupLeave(message->new_cli,command_split[1],command_split[2],message)){
			TLSSendMsg(ssl,"1");
		}
		else
			TLSSendMsg(ssl,"0");
	}
	else if(command_split[0]=="logout"){
		command_object>>command_split[1];

		if(Logout(command_split[1])){
			TLSSendMsg(ssl,"1");
		}
		else
			TLSSendMsg(ssl,"0");
	}
	else if(command_split[0]=="Sync"){
		command_object>>command_split[1];

		SyncRecv(ssl,command_split[1]);
	}
	else if(command_split[0]=="SyncAll"){
		SyncAllHandler(mysequence_i,tracker_info);
	}
	else if(command_split[0]=="give_sha"){
		command_object>>command_split[1];
		command_object>>command_split[2];
		command_object>>command_split[3];

		string data=SendSHA(message->new_cli,message,command_split[1],command_split[2],command_split[3]);
		TLSSendMsg(ssl,data);
	}
	else if(command_split[0]=="give_seeders"){
		command_object>>command_split[1];
		command_object>>command_split[2];
		command_object>>command_split[3];

		string data=SendSeeders(message->new_cli,message,command_split[1],command_split[2],command_split[3]);
		TLSSendMsg(ssl,data);
	}
	else if(command_split[0]=="give_details"){
		command_object>>command_split[1];

		string data=SendDetails(message->new_cli,message,command_split[1]);
		TLSSendMsg(ssl,data);
	}
	else if(command_split[0]=="send_full_path"){
		command_object>>command_split[1];
		command_object>>command_split[2];
		command_object>>command_split[3];

		string data=GetFullPath(message->new_cli,message,command_split[1],command_split[2],command_split[3]);
		TLSSendMsg(ssl,data);
	}
	else if(command_split[0]=="add_file"){
		command_object>>command_split[1];
		command_object>>command_split[2];
		command_object>>command_split[3];
		command_object>>command_split[4];

		UpdateDownload(message->new_cli,message,command_split[1],command_split[2],command_split[3],command_split[4]);
	}
	else if(command_split[0]=="complete"){
		command_object>>command_split[1];
		command_object>>command_split[2];
		command_object>>command_split[3];
		command_object>>command_split[4];

		CompleteDownload(message->new_cli,message,command_split[1],command_split[2],command_split[3],command_split[4]);
	}
	else if(command_split[0]=="show_downloads"){
		command_object>>command_split[1];

		string data=ShowDownloads(message->new_cli,message,command_split[1]);
		TLSSendMsg(ssl,data);
	}
	else{}

	TLSClose(ssl);
	close(message->new_cli);
	return NULL;
}

void *TrackerServer(void *pointer){
	int mysequence_i=*((int*) pointer);
	struct sockaddr_in server,client;
	int sock,new_cli;
	pthread_t tid[1000];
	int counter=0;

	int sockaddr_len=sizeof(struct sockaddr_in);
	socklen_t len=sizeof(struct sockaddr_in);
	string my_port=tracker_info[mysequence_i].second;
	
	if((sock=socket(AF_INET,SOCK_STREAM,0))==-1){
		perror("server socket: ");
		exit(-1);
	}

	// Without this, a just-restarted tracker can transiently fail to bind
	// its own port with EADDRINUSE while the OS finishes releasing the
	// previous listening socket.
	int reuse=1;
	setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));

	server.sin_family=AF_INET;
	server.sin_port=htons(atoi((tracker_info[mysequence_i].second).c_str()));
	// server.sin_addr.s_addr=INADDR_ANY;
	server.sin_addr.s_addr=inet_addr((tracker_info[mysequence_i].first).c_str());
	bzero(&server.sin_zero,8);

	if((::bind(sock,(struct sockaddr*)&server,sockaddr_len))==-1){
		perror("Bind");
		exit(-1);
	}

	if(listen(sock,5)==-1){
		perror("Listen");
		exit(-1);
	}

	// cout<<my_port<<endl;
	while(true){
		if((new_cli=accept(sock,(struct sockaddr*)&client,&len))==-1){
			perror("accept");
			exit(-1);
		}

		Message* message=new Message;
		message->new_cli=new_cli;
		message->client=client;
		// string temp1(tontohs(client.sin_port));
		message->client_port=to_string(ntohs(client.sin_port));
		string temp(inet_ntoa(client.sin_addr));
		message->client_ip=temp;

		auto pid=pthread_create(&tid[counter],NULL,TrackerKernel,(void *)message);
		if(pid!=0){
			perror("thread failed");
			exit(-1);
		}
		++counter;
		counter=counter%1000;

		if(counter>50){
			for(int j=0;j<counter;++j){
				pthread_join(tid[j],NULL);
			}
			counter=0;
		}
	}
}

void print_all(){
// 	unordered_map<string,string> credentials;
// unordered_map<string,pair<string,string> >online_users;
// set<string> online;
// unordered_map<string,string> groups;
// vector<pair<string,string>> tracker_info;

	FetchDetails();

	cout<<"##### credentials"<<endl;
	for(auto i:credentials){
		cout<<i.first<<" "<<i.second<<endl;
	}
	cout<<"##### online_users"<<endl;
	for(auto i:online_users){
		cout<<i.first<<" "<<i.second.first<<" "<<i.second.second<<endl;
	}
	cout<<"##### groups"<<endl;
	for(auto i:groups){
		cout<<i.first<<" "<<i.second<<endl;
	}
	cout<<"##### online"<<endl;
	for(auto i:online){
		cout<<i<<endl;
	}
	cout<<"##### tracker_info"<<endl;
	for(auto i:tracker_info){
		cout<<i.first<<" "<<i.second<<endl;
	}

	cout<<"##### pending"<<endl;
	for(auto i:pending_group_requests){
		cout<<i.first<<" "<<i.second<<endl;
	}
}

int main(int argc, char** argv){

	bool flag=true;
	string command,line,temp_ip,temp_port;
	pthread_t tid;

	string filepath=argv[1];
	string mysequence=argv[2];
	mysequence_i=atoi(mysequence.c_str())-1;

	ifstream infile;
	infile.open(filepath,ios::in);

	while(getline(infile,line)){
		// cout<<line<<endl;
		stringstream line_object(line);
		line_object>>temp_ip;
		line_object>>temp_port;
		tracker_info.push_back(make_pair(temp_ip,temp_port));
	}

	// Certs live in a "certs" directory alongside the tracker_info.txt file
	// (project root for a bare-metal run, /app for the Docker image) -
	// see certs/generate-dev-cert.sh.
	size_t last_slash=filepath.find_last_of('/');
	string certdir=(last_slash==string::npos) ? "certs" : filepath.substr(0,last_slash)+"/certs";

	TLSGlobalInit();
	server_ctx=TLSServerContext(certdir+"/tracker.crt",certdir+"/tracker.key");
	client_ctx=TLSClientContext(certdir+"/tracker.crt");

	if(pthread_mutex_init(&file_lock, NULL) != 0){
		perror("Mutex Failed");
		exit(-1);
	}
	if(pthread_mutex_init(&global_lock, NULL) != 0){
		perror("Mutex Failed");
		exit(-1);
	}

	FetchDetails();
	SyncAll(mysequence_i,tracker_info);

	auto pid=pthread_create(&tid,NULL,TrackerServer,&mysequence_i);
	if(pid!=0){
		perror("Thread creation failed");
		exit(-1);
	}

	while(flag){
		cin>>command;
		if(cin.eof()){
			// No interactive controlling terminal (e.g. started in the
			// background). Block here instead of busy-spinning on a
			// closed stdin, while the server thread keeps accepting
			// connections.
			pthread_join(tid,NULL);
			break;
		}
		if(command=="quit"){
			flag=false;
		}
		if(command=="print"){
			print_all();
		}
	}

	pthread_cancel(tid);
	pthread_mutex_destroy(&file_lock);
	pthread_mutex_destroy(&global_lock);
	return 0;
}