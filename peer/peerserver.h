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

using namespace std;

#define MAX_SIZE2 65535
#define CHUNK_SIZE2 524288
#define SMALL_CHUNK_SIZE2 1024

#ifndef __peerserver_H_INCLUDED__
#define __peerserver_H_INCLUDED__

void* ClientServer(void* pointer);
void* ClientServerKernel(void* pointer);
vector<string> split(string data,char delim);
pair<string,int> CheckTracker(vector<pair<string,int> > tracker_data);
vector<pair<string,int> >Conv(vector<string> split_vector);
string GetFilePath(pair<string,int> server_final,string groupname,string filename,string username);
void TransferFunction(vector<string> split_vector,struct Message* message);

#endif