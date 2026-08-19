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
#include<math.h>
#include<algorithm>

#include <openssl/sha.h>
#include <openssl/evp.h>

using namespace std;

#define MAX_SIZE1 65535
#define CHUNK_SIZE1 524288
#define SMALL_CHUNK_SIZE1 1024

// string username;

#ifndef __peerdownload_H_INCLUDED__
#define __peerdownload_H_INCLUDED__

void DownloadFile(string groupname, string filename, string filepath,string username,string myip,string si,int sp,string serverpath);
vector<string> split2(string data,char delim);
void GetChunks(struct FILEDATA* filemeta);

#endif