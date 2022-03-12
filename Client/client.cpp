#include <netinet/in.h>
#include <cstring>
#include <arpa/inet.h>
#include  <unistd.h>
#include <iostream>
#include "../Managers/managers.h"
#define CERT_DIR (string )"../Client/Certs/"
#define CA_CERT (string) "CA.pem"
#define CA_CRL "CA_crl.pem"
using namespace std;
using namespace Managers;
void usage();
int authenticate_to_server(int server_socket,string username);
int verify_cert(X509*);
EVP_PKEY* save_cert(X509* cert);
//
// Created by crl on 2/19/22.
//
int main(){
    int server_socket;
    int not_used;
    struct sockaddr_in server_address;
    string username;
    string  command;
    bool done = false;
    //TODO: parsing parameters
    //open socket
    memset((void*)&server_address,0,(size_t) sizeof(server_address));
    server_address.sin_family= AF_INET; //kind of socket
    server_address.sin_port = htons(SERVER_PORT); //server port
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");  //server IP
    server_socket = socket(AF_INET,SOCK_STREAM,0);
    ISLESSTHANZERO(server_socket,"Opening socket failed")
    cout << "Socket opened" << endl;
    //connect to server
    not_used = connect(server_socket,(struct sockaddr*) &server_address,sizeof(server_address));
    ISLESSTHANZERO(not_used,"Connect failed")
    cout << "type your username: " << endl;
    cin >> username;
    ISNOT(cin,"Ooops! something went wrong")
    cout << "authentication in progress..." << endl;
   // X509* cert = Managers::CryptoManager::open_certificate((string) "../Server/Docs/SecureChat_cert.pem");
    //verify_cert(cert);
    //exit(0);
    not_used = authenticate_to_server(server_socket,username);
    if(!not_used){
        cerr << "Authentication failed: cannot proceed!" << endl;
        close(server_socket);
        exit(EXIT_FAILURE);
    }


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

int authenticate_to_server(int server_socket, string username){
    int result;
    Message *reply;
    Message* message = new Message();
    message->setSender(username);
    message->setType(AUTH_REQUEST);
    uint32_t nonce ;
    X509* server_cert = nullptr;
    CryptoManager::generate_nonce(&nonce);
    message->getPayload()->setNonce(nonce);
    //1st handshake message
    result = SocketManager::send_message(server_socket,message);
    delete message;
    if (result <= 0)
        return 0;
    //2nd handshake message
    reply = SocketManager::read_message(server_socket);
    if(!reply or reply->getType() == ERROR)
        return 0;
    //verify received certificate
    server_cert = reply->getPayload()->getCert();
    //X509* server_cert = Managers::CryptoManager::open_certificate((string) "../Server/Docs/SecureChat_cert.pem");

    cout << "verifying sever's cert..." << endl;
    //result = verify_cert(server_cert);
    cout << "result: " << (result == 1) << endl;
    EVP_PKEY* server_pub_key = X509_get_pubkey(server_cert);
    EVP_PKEY* eph_pub_key = reply->getPayload()->getTPubKey();
    unsigned char* signature = reply->getPayload()->getSignature();
    uint32_t signature_length = reply->getSignatureLen();
    result = CryptoManager::verify_signed_pubKey(eph_pub_key,nonce,server_pub_key,signature,signature_length);
    cout << "hhhh " << result << endl;

    return result;

}

EVP_PKEY* save_cert(X509* cert){
    BIO* b = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(b,cert);
    long size = BIO_pending(b);
    char* buff =  new char[size];
    BIO_read(b,buff,size);
    FILE* f = fopen("/tmp/tmp_cert.pem","w");

    fclose(f);
    f = fopen("../Server/Docs/tmp_cert.pem","r");
    EVP_PKEY* pkey = PEM_read_PUBKEY(f,NULL,NULL,NULL);
    return pkey;


}
