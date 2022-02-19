#include <netinet/in.h>
#include <cstring>
#include <arpa/inet.h>
#include  <unistd.h>
#include <iostream>
#include "../Utility/utility.h"

using namespace std;
//
// Created by crl on 2/19/22.
//
int main(){
    int server_socket;
    int not_used;
    struct sockaddr_in server_addr;
    //TODO: parsing parameters

    memset((void*)&server_addr,0,(size_t) sizeof(server_addr));

    server_addr.sin_family= AF_INET; //kind of socket
    server_addr.sin_port = htons(SERVER_PORT); //server port
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");  //server IP

    server_socket = socket(AF_INET,SOCK_STREAM,0);

    ISLESSTHANZERO(server_socket,"Opening socket failed")

    cout << "Socket opened" << endl;

    not_used = connect(server_socket,(struct sockaddr*) &server_addr,sizeof(server_addr));
    ISLESSTHANZERO(not_used,"Connect failed")
    string str = "hi server how are you?";
    size_t size = str.length();
    size_t tmp = write(server_socket,str.c_str(),size);
    cout << "written " << tmp << endl;
    char* reply = new char [MAX_CHARS + 1];
    tmp = read(server_socket,reply, MAX_CHARS);
    cout << "Got " << reply << " " << tmp << " bytes" << endl;
    free(reply);
    close(server_socket);
    return  0;
}
