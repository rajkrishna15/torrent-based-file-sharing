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

#include "tls.h"

using namespace std;

#define MAX_SIZE 65535

#ifndef __trackersync_H_INCLUDED__
#define __trackersync_H_INCLUDED__

// Defined in tracker.cpp; used here to connect out to the sibling tracker.
extern SSL_CTX* client_ctx;

// pair<string,string> OtherServerDetails(int mysequence_i);
void Sync(string filename,int mysequence_i,vector<pair<string,string>> tracker_info);
bool IsOnline(int target_seq,vector<pair<string,string>> tracker_info);
int GetTracker2(int mysequence_i);
void SyncRecv(SSL* ssl,string filename);
void SyncAll(int mysequence_i,vector<pair<string,string>> tracker_info);
void SyncAllHandler(int mysequence_i,vector<pair<string,string>> tracker_info);

#endif
