#include <iostream>
#include <netinet/in.h>
#include  <unistd.h>
#include <cstring>
#include <fstream>
#include <vector>
#include "Classes/Session.h"
#include "../Managers/managers.h"
#define USERS_FILE "../Server/Docs/users.txt"
#define USERS_PUBKEY "../Server/Docs/"
#define SERVER_PVT_KEY "SecureChat_key.pem"
#define SERVER_CERT "SecureChat_cert.pem"

using namespace std;
using namespace Managers;
int update_max(fd_set set,int fd_max);
Session* configure_server(void);
vector<string> parse_line(string line);
EVP_PKEY* read_public_key(string username);
int manage_message(int socket, Message* message);
void disconnect_client(int socket,fd_set* client_set,int* fd_num);

//global
Session* session;
int main() {
    int master_socket;
    //client's socket
    int fd_c;
    size_t n_byte_read;
    int not_used;
    fd_set client_set;
    fd_set  read_set;
    //socket address
    struct sockaddr_in address;
    session = configure_server();

    master_socket = socket(AF_INET,SOCK_STREAM,0);
    ISLESSTHANZERO(master_socket,"Opening master socket failed");
    cout << "Master socket opened" << endl;
    memset((void*)&address,0,(size_t) sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( SERVER_PORT );
    not_used = bind(master_socket,(struct sockaddr *)&address,sizeof(address));
    ISLESSTHANZERO(not_used,"Biding address to master socket failed")
    not_used = listen(master_socket, SOMAXCONN);
    ISLESSTHANZERO(not_used,"Listen failed")
    cout << "Master socket ready to accept connections" << endl;
    FD_ZERO(&client_set);
    FD_SET(master_socket,&client_set);
    int fd_num = master_socket;
    while (true){
        read_set = client_set;
        cout << "Sleep on select" <<endl;
        not_used = select(fd_num + 1,&read_set, nullptr, nullptr, nullptr);
        ISLESSTHANZERO(not_used,"select failed")
        //find the ready socket
        for(int fd = 3; fd <= fd_num;fd ++){
            if(FD_ISSET(fd,&read_set)){
                if(fd == master_socket){
                    fd_c = accept(fd, nullptr,nullptr);
                    FD_SET(fd_c,&client_set);
                    if(fd_c > fd_num ) fd_num = fd_c;
                    cout << "Accepted connection " << endl;
                } else{
                    Message* message = SocketManager::read_message(fd);
                    if(!message){ //client done or i/o error
                        disconnect_client(fd,&client_set,&fd_num);
                    }
                    else{
                        int r = manage_message(fd,message);
                        if(!r)
                            disconnect_client(fd,&client_set,&fd_num);
                    }
                }

            }
        }
    }
    return 0;
}


int update_max(fd_set set,int fd_max){
    for(int i = fd_max; i>= 0 ; i--){
        if(FD_ISSET(i,&set)) return i;
    }
    return -1;
}

Session* configure_server(void){
    Session* session = new Session();
    vector<string> usernames;
    string line;
    X509* cert;
    fstream users_file(USERS_FILE);
    cout << USERS_FILE << endl;
    cout << users_file.is_open() << endl;
    while(users_file.is_open() && getline(users_file,line)){
        usernames = parse_line(line);
        for(auto username : usernames) {
            User* user = new User();
            user->setUserName(username);
            EVP_PKEY* pub_key = read_public_key(username);
            user->setPublicKey(pub_key);
            session->add_user(user);
        }
    }
    users_file.close();
    //now set server private key
    FILE* file;
    EVP_PKEY* pvt_key;
    string filename = (string) USERS_PUBKEY + SERVER_PVT_KEY;
    file = fopen(filename.c_str(),"r");
    ISNOT(file,"opening server private key fail failed")
    pvt_key = PEM_read_PrivateKey(file,NULL,NULL,NULL);
    fclose(file);
    ISNOT(pvt_key,"reading server pvt key failed")
    session->setServerPvtKey(pvt_key);
    //set server cert
    string cert_path = (string) USERS_PUBKEY + SERVER_CERT;
    cert = Managers::CryptoManager::open_certificate(cert_path);
    ISNOT(cert,"loading server certificate failed ")
    session->setServerCert(cert);
    return session;
}

vector<string> parse_line(string line){
    vector<string> tokens;
    string splitting = ",";
    size_t index;
    while((index = line.find(splitting)) != string::npos){
        tokens.push_back(line.substr(0,index));
        //remove last token and splitting char
        line.erase(0,index + splitting.length());
    }
    //last element
    if(line.length() > 0)
        tokens.push_back(line);
    return tokens;
}

EVP_PKEY* read_public_key(string username){
    EVP_PKEY* public_key;
    FILE* file;
    string filename = (string) USERS_PUBKEY + username + ".pem";
    file = fopen(filename.c_str(),"r");
    ISNOT(file,"opening users public key failed")
    public_key = PEM_read_PUBKEY(file,NULL,NULL,NULL);
    //cout << "size: " << EVP_PKEY_size(public_key) << endl;
    //BIO_dump_fp(stdout,(const char*) public_key, EVP_PKEY_size(public_key));
    fclose(file);
    return public_key;
}
int manage_message(int socket, Message* message){
    string sender = message->getSender();
    Message *reply = new Message();
    uint32_t signature_size =0;
    EVP_PKEY * eph_pubkey;
    EVP_PKEY * eph_pvtkey;
    unsigned char* signature;
    int result = 0;
    uint32_t encrypted_k_as_size;
    unsigned char* encrypted_k_as ;
    pair<EVP_PKEY*,EVP_PKEY*> eph_keys;
    uint32_t eph_pub_key_bytes_size;
    unsigned char* eph_pub_key_bytes;
    unsigned char* to_verify;
    unsigned char* plaintext;
    size_t plain_size;
    EVP_PKEY* client_pub_key;
    switch (message->getType()) {
        case AUTH_REQUEST:
            if(!session->is_registered(sender)){
                delete message;
                cerr << "WRONG USERNAME" << endl;
                reply->setType(ERROR);
                reply->getPayload()->setErrorMessage((string)"Invalid username");
                SocketManager::send_message(socket,reply);
                delete reply;
                break; //returns invalid username
            }

            eph_pubkey = EVP_PKEY_new();
            eph_pvtkey = EVP_PKEY_new();
            result = CryptoManager::generate_ephemeral_rsa(&eph_pubkey,&eph_pvtkey);
            if(result){
                signature = CryptoManager::sign_pubKey(eph_pubkey,session->getServerPvtKey(),
                                           message->getPayload()->getNonce(),&signature_size);
                if(signature){
                    reply->setType(AUTH_RESPONSE);
                    reply->setSignatureLen(signature_size);
                    reply->getPayload()->setSignature(signature);
                    reply->getPayload()->setTPubKey(eph_pubkey);
                    reply->getPayload()->setCert(session->getServerCert());
                    result = SocketManager::send_message(socket,reply);
                    if(result){
                        pair<EVP_PKEY*,EVP_PKEY*> ephemeral_pair;
                        ephemeral_pair.first = eph_pubkey;
                        ephemeral_pair.second = eph_pvtkey;
                        //save ephemeral keys to complete the handshake
                        session->add_ephemeral_keys(sender,ephemeral_pair);
                    }
                }

            }
            break;
        case AUTH_KEY_EXCHANGE:
            if(!session->is_in_handshake(message->getSender())){
                delete message;
                cerr << "NOT HANDSHAKE" << endl;
                reply->setType(ERROR);
                reply->getPayload()->setErrorMessage((string)"Invalid username");
                SocketManager::send_message(socket,reply);
                delete reply;
                break; //user not in handshake
            }
            encrypted_k_as_size = message->getCTxtLen();
            encrypted_k_as = message->getPayload()->getCiphertext();
            eph_keys = session->get_ephemeral_keys(message->getSender());
            uint32_t eph_pub_key_bytes_size;
            result = CryptoManager::pkey_to_bytes(eph_keys.first,&eph_pub_key_bytes,&eph_pub_key_bytes_size);
            IF_MANAGER_FAILED(result,"obtaining pkey_to_bytes failed",0)
            to_verify = new unsigned char[encrypted_k_as_size + eph_pub_key_bytes_size];
            ISNOT(to_verify,"allocating to_sign failed")
            //copy them into one buffer to be signed
            memmove(to_verify,encrypted_k_as,encrypted_k_as_size);
            //move on pointer to put the rest
            memmove(to_verify + encrypted_k_as_size ,eph_pub_key_bytes,eph_pub_key_bytes_size);
            //bytes have been copied free memory
            free(encrypted_k_as);
            free(eph_pub_key_bytes);
            //verify client signature on ciphertext
            signature = message->getPayload()->getSignature();
            signature_size = message->getSignatureLen();
            client_pub_key = session->get_user(sender)->getPublicKey();
            plain_size = encrypted_k_as_size + eph_pub_key_bytes_size;
            result = CryptoManager::verify_signature(signature,signature_size,to_verify, plain_size,
                                            client_pub_key);
            cout << "verify client's signature " << result << endl;
            //decrypt session key
            CryptoManager::rsa_decrypt(encrypted_k_as,encrypted_k_as_size,&plaintext,
                                       &plain_size,eph_keys.second);
            for(int i=0; i < KEY_LENGTH; i++)
                cout << (int) plaintext[i] << endl;
            break;
        default:
            cerr << "wrong type!!" << endl;

    }
    return result;
}

void disconnect_client(int socket,fd_set* client_set,int* fd_num){
    FD_CLR(socket,client_set);
    *fd_num = update_max(*client_set,*fd_num);
    ISLESSTHANZERO(*fd_num,"update_max failed")
    close(socket);
    //TODO: put user offline
    cout << "Client done!!" << endl;
}

