#include <netinet/in.h>
#include <cstring>
#include <arpa/inet.h>
#include  <unistd.h>
#include <iostream>
#include "../Common/utility.h"
#include "../Managers/managers.h"
#define CERT_DIR (string )"../Client/Certs/"
#define CA_CERT (string) "CA.pem"
#define CA_CRL "CA_crl.pem"
using namespace std;
using namespace Managers;
int verify_cert(X509*);
//
// Created by crl on 2/19/22.
//
int main(){
    int server_socket;
    int not_used;
    struct sockaddr_in server_address;
    //TODO: parsing parameters

    memset((void*)&server_address,0,(size_t) sizeof(server_address));
    server_address.sin_family= AF_INET; //kind of socket
    server_address.sin_port = htons(SERVER_PORT); //server port
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");  //server IP
    server_socket = socket(AF_INET,SOCK_STREAM,0);
    ISLESSTHANZERO(server_socket,"Opening socket failed")
    cout << "Socket opened" << endl;

    not_used = connect(server_socket,(struct sockaddr*) &server_address,sizeof(server_address));
    ISLESSTHANZERO(not_used,"Connect failed")
    string str = "hi server how are you?";
    size_t size = str.length();
    int tmp = SocketManager::write_n(server_socket,size,(void*) str.c_str());
    cout << "written with result " << tmp << endl;
    char* reply = new char [MAX_CHARS + 1];
    tmp = SocketManager::read_n(server_socket,32,(void*) reply);
    cout << "Got " << reply << " " << tmp << " bytes" << endl;
    free(reply);
    close(server_socket);
    return  0;
}

int  verify_cert(X509* cert){
    X509* ca_cert = CryptoManager::open_certificate(CERT_DIR + CA_CERT);
    ISNOT(ca_cert,"opening CA certificate failed")
    X509_CRL* ca_crl = CryptoManager::open_crl(CERT_DIR + CA_CRL);
    ISNOT(ca_crl,"opening CA_crl failed")
    int result = CryptoManager::verify_cert(ca_cert,ca_crl,cert);
    return result;
}
