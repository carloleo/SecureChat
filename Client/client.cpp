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
int prepare_third_message(EVP_PKEY*,Message*);

//global
EVP_PKEY *pvt_client_key = nullptr;
unsigned char* sever_session_key = nullptr;
string username;
//
// Created by crl on 2/19/22.
//
int main(){
    int server_socket;
    int not_used;
    struct sockaddr_in server_address;
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
    //IDE does not allow to open promt
    string pwd;
    //cout << "pwd" << endl;
    //cin >> pwd;
    //X509* cert = Managers::CryptoManager::open_certificate((string) "../Server/Docs/SecureChat_cert.pem");
    //verify_cert(cert);
    //exit(0);
    //reading client pvt key
    FILE* file;
    string filename = (string)  CERT_DIR + username + "_key.pem" ;
    file = fopen(filename.c_str(),"r");
    ISNOT(file,"opening client private key fail failed")
    pvt_client_key = PEM_read_PrivateKey(file,NULL,NULL,NULL/*(void*) pwd.c_str()*/);
    fclose(file);
    ISNOT(pvt_client_key,"reading client pvt key failed")
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
    Message *second_message;
    Message* first_message;
    NEW(first_message,new Message(),"first message")
    first_message->setSender(username);
    first_message->setType(AUTH_REQUEST);
    uint32_t nonce ;
    X509* server_cert = nullptr;
    CryptoManager::generate_nonce(&nonce);
    first_message->getPayload()->setNonce(nonce);
    //1st handshake message
    result = SocketManager::send_message(server_socket,first_message);
    delete first_message;
    if (result <= 0)
        return 0;
    //2nd handshake message
    second_message = SocketManager::read_message(server_socket);
    if(!second_message or second_message->getType() == ERROR)
        return 0;
    //verify received certificate
    server_cert = second_message->getPayload()->getCert();
    cout << "verifying sever's cert..." << endl;
    result = verify_cert(server_cert);
    cout << "result: " << (result == 1 ? "valid" : "wrong") << endl;
    EVP_PKEY* server_pub_key = X509_get_pubkey(server_cert);

    EVP_PKEY* eph_pub_key = second_message->getPayload()->getTPubKey();
    unsigned char* signature = second_message->getPayload()->getSignature();
    uint32_t signature_length = second_message->getSignatureLen();
    //verify signature on ephemeral public key
    result = CryptoManager::verify_signed_pubKey(eph_pub_key,nonce,server_pub_key,signature,
                                                 signature_length);
    IF_MANAGER_FAILED(result,"verifying ephemeral signed public key failed",0)

    //send third message
    Message* third_message;
    NEW(third_message,new Message(),"third message");
    result = prepare_third_message(eph_pub_key,third_message);
    IF_MANAGER_FAILED(result,"prepare third message failed",0)
    result = SocketManager::send_message(server_socket,third_message);
    //TODO read confirmation message and clean up
    return result;

}
int prepare_third_message(EVP_PKEY* eph_pub_key,Message* msg){
    int result;
    //session key
    unsigned char* master_secret;
    NEW(master_secret,new unsigned char[KEY_LENGTH],"master_secret")
    result = CryptoManager::generate_random_bytes(master_secret,KEY_LENGTH);
    IF_MANAGER_FAILED(result,"generating session key failed",0)
    //encrypt session key by server ephemeral public key
    unsigned char* encrypted_master_secret;
    size_t encrypted_ms_size;
    result = CryptoManager::rsa_encrypt(&encrypted_master_secret, &encrypted_ms_size, master_secret,
                                        KEY_LENGTH, eph_pub_key);
    IF_MANAGER_FAILED(result,"encrypting session key failed",0)
    //get bytes from ephemeral server public key
    unsigned char* eph_pub_key_bytes;
    uint32_t eph_pub_key_bytes_size;
    result = CryptoManager::pkey_to_bytes(eph_pub_key,&eph_pub_key_bytes,&eph_pub_key_bytes_size);
    IF_MANAGER_FAILED(result,"pkey_to_bytes failed",0)
    //sign both of them
    unsigned char* to_sign;
    NEW(to_sign,new unsigned char[encrypted_ms_size + eph_pub_key_bytes_size],"to_sign")
    //copy them into one buffer to be signed
    memmove(to_sign, encrypted_master_secret, encrypted_ms_size);
    //move on pointer to put the rest
    memmove(to_sign + encrypted_ms_size , eph_pub_key_bytes, eph_pub_key_bytes_size);
    free(eph_pub_key_bytes);


    //sign
    unsigned char* signature;
    uint32_t signature_len;
    uint32_t plain_size = encrypted_ms_size + eph_pub_key_bytes_size;
    signature = CryptoManager::sign(to_sign,plain_size,pvt_client_key,
                        &signature_len);
    IF_MANAGER_FAILED(signature_len,"signing to_sign failed",0)
    msg->setType(AUTH_KEY_EXCHANGE);
    msg->setSender(username);
    //set encrypted session key
    msg->setCTxtLen(encrypted_ms_size);
    msg->getPayload()->setCiphertext(encrypted_master_secret);
    //set signature
    msg->setSignatureLen(signature_len);
    msg->getPayload()->setSignature(signature);
    //generate session key
    sever_session_key = CryptoManager::compute_session_key(master_secret,KEY_LENGTH);
    IF_MANAGER_FAILED(sever_session_key,"generating session key failed",0)

    for(int i=0; i < KEY_LENGTH; i++)
        cout << (int) sever_session_key[i] << endl;
    return 1;
}
/*EVP_PKEY* save_cert(X509* cert){
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
*/
