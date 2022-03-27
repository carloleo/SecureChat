#include <iostream>
#include <netinet/in.h>
#include <unistd.h>
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
int check_client_message(Message* message);

//global
Session* session;
int fd_num;
fd_set client_set;
int main() {
    int master_socket;
    //client's socket
    int fd_c;
    size_t n_byte_read;
    int not_used;
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
    fd_num = master_socket;
    while (true){
        read_set = client_set;
        //cout << "Sleep on select" <<endl;
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
                        if(!r) {
                            disconnect_client(fd, &client_set, &fd_num);
                            //TODO: send notification PEER_DISCONNECTED
                        }
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
    while(users_file.is_open() && getline(users_file,line)){
        usernames = parse_line(line);
        for(auto username : usernames) {
            User* user;
            NEW(user,new User(),"user")
            user->setUserName(username);
            cout << username << endl;
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
    string username_sender = message->getSender();
    User* sender;
    User* recipient;
    Message *reply;
    uint32_t signature_size =0;
    EVP_PKEY * eph_pubkey;
    EVP_PKEY * eph_pvtkey;
    unsigned char* signature;
    int result = 0;
    uint32_t encrypted_ms_size;
    unsigned char* encrypted_master_secret ;
    unsigned char* session_key;
    unsigned char* digest;
    pair<EVP_PKEY*,EVP_PKEY*> eph_keys;
    uint32_t eph_pub_key_bytes_size;
    unsigned char* eph_pub_key_bytes;
    unsigned char* to_verify;
    unsigned char* plaintext;
    size_t plain_size;
    EVP_PKEY* client_pub_key;
    unsigned char* aad ;
    unsigned char* ciphertext;
    unsigned char* auth_tag;
    unsigned char* iv ;
    uint32_t server_sn = 0;
    string online_users;
    size_t len;
    int cipher_len = 0;
    bool peer_authentication= false;
    NEW(reply,new Message(),"reply")
    //TODO: MANAGE ERROR MESSAGES
    switch (message->getType()) {
        case AUTH_REQUEST:
            if(!session->is_registered(username_sender) or
                    session->get_user(username_sender)->isOnline()){
                cerr << "WRONG USERNAME" << endl;
                return 0; //returns invalid username
            }

            eph_pubkey = EVP_PKEY_new();
            if(!eph_pubkey)
                return 0;
            eph_pvtkey = EVP_PKEY_new();
            if(!eph_pvtkey)
                return 0;
            result = CryptoManager::generate_ephemeral_rsa(&eph_pubkey,&eph_pvtkey);
            if(result){
                signature = CryptoManager::sign_pubKey(eph_pubkey,session->getServerPvtKey(),
                                           message->getPayload()->getNonce(),&signature_size);
                if(signature){
                    reply->setType(AUTH_RESPONSE);
                    reply->setSignatureLen(signature_size);
                    reply->getPayload()->setSignature(signature);
                    reply->getPayload()->setPubKey(eph_pubkey);
                    reply->getPayload()->setCert(session->getServerCert());
                    result = SocketManager::send_message(socket,reply);
                    if(result){
                        pair<EVP_PKEY*,EVP_PKEY*> ephemeral_pair;
                        ephemeral_pair.first = eph_pubkey;
                        ephemeral_pair.second = eph_pvtkey;
                        //save ephemeral keys to complete the handshake
                        session->add_ephemeral_keys(username_sender,ephemeral_pair);
                    }
                }

            }
            break;
        case AUTH_KEY_EXCHANGE:
            if(!session->is_in_handshake(message->getSender())){
                delete message;
                cerr << "NOT HANDSHAKE" << endl;
                return 0;
            }
            encrypted_ms_size = message->getCTxtLen();
            encrypted_master_secret = message->getPayload()->getCiphertext();
            eph_keys = session->get_ephemeral_keys(message->getSender());
            uint32_t eph_pub_key_bytes_size;
            result = CryptoManager::pkey_to_bytes(eph_keys.first,&eph_pub_key_bytes,&eph_pub_key_bytes_size);
            IF_MANAGER_FAILED(result,"obtaining pkey_to_bytes failed",0)
            NEW(to_verify,new unsigned char[encrypted_ms_size + eph_pub_key_bytes_size],"to_verify")
            //copy them into one buffer to be verified
            memmove(to_verify,encrypted_master_secret,encrypted_ms_size);
            //move on pointer to put the rest
            memmove(to_verify + encrypted_ms_size ,eph_pub_key_bytes,eph_pub_key_bytes_size);
            //bytes have been copied free memory
            //free(encrypted_master_secret);
            delete eph_pub_key_bytes;
            //verify client signature on ciphertext
            signature = message->getPayload()->getSignature();
            signature_size = message->getSignatureLen();
            client_pub_key = session->get_user(username_sender)->getPublicKey();
            plain_size = encrypted_ms_size + eph_pub_key_bytes_size;
            result = CryptoManager::verify_signature(signature,signature_size,to_verify, plain_size,
                                            client_pub_key);
            IF_MANAGER_FAILED(result,"verifying client signature failed",0)
            //decrypt master secret  key
            result = CryptoManager::rsa_decrypt(encrypted_master_secret,encrypted_ms_size,&plaintext,
                                       &plain_size,eph_keys.second);
            //free ephemeral keys
            session->destroy_ephemeral_keys(username_sender);
            IF_MANAGER_FAILED(result,"decrypting master secret failed",0)
            //plaintext is the shared master secret
            session_key = CryptoManager::compute_session_key(plaintext,plain_size);
            IF_MANAGER_FAILED(session_key,"computing session key failed",0)
            //destroy master secret
            destroy_secret(plaintext,plain_size);
            //set user's session key
            sender = session->get_user(username_sender);
            sender->setSessionKey(session_key);
            //initializing sender communication state
            sender->setIsOnline(true);
            sender->setSnServer(0);
            sender->setSnUser(0);
            sender->setSocket(socket);
            //retrieve online users
            online_users = session->get_online_users();
            //encrypt message
            result = SocketManager::send_encrypted_message(socket,sender->getSnServer(),session_key,
                                                           online_users,AUTH_KEY_EXCHANGE_RESPONSE);
            IF_MANAGER_FAILED(result,"sending last handshake failed",0);
            sender->increment_server_sn();
            delete to_verify;
            break;
        case REQUEST_TO_TALK:
            //check authenticity
            result = check_client_message(message);
            if(!result)
                return result;
            sender = session->get_user(username_sender);
            recipient = session->get_user(message->getRecipient());
            result = false;
            if(recipient->isOnline()) {
                iv = CryptoManager::generate_iv();
                //free because they will be replaced
                delete message->getIv();
                delete message->getPayload()->getAuthTag();
                message->setIv(iv);
                message->setSequenceN(recipient->getSnServer());
                result = SocketManager::send_authenticated_message(recipient->getSocket(), message,
                                                                   recipient->getSessionKey());
                //until the request gets closed they will be busy
                if(result) {
                    recipient->setIsBusy(true);
                    sender->setIsBusy(true);
                    recipient->increment_server_sn();
                    session->open_chat(recipient->getUserName(),sender->getUserName());
                }
            }
            //forwarding request to talk failed
            if(!result){
                iv = CryptoManager::generate_iv();
                reply->setType(ERROR);
                reply->setErrCode(FORWARD_REQUEST_FAIL);
                reply->setIv(iv);
                reply->setSequenceN(sender->getSnServer());
                result = SocketManager::send_authenticated_message(sender->getSocket(),
                                                                   reply,sender->getSessionKey());
                IF_MANAGER_FAILED(result,"REQUEST_OK sending forward error failed",0);
            }
            break;
        case REQUEST_OK:
            //check authenticity
            result = check_client_message(message);
            if(!result)
                return result;
            sender = session->get_user(username_sender);
            recipient = session->get_user(message->getRecipient());
            result = false;
            if(recipient->isOnline()) {
                iv = CryptoManager::generate_iv();
                IF_MANAGER_FAILED(iv, "REQUEST_OK generating iv failed", 0)
                //owner public key
                reply->setSender(username_sender);
                reply->setType(PEER_PUB_KEY);
                reply->getPayload()->setPubKey(sender->getPublicKey());
                reply->setIv(iv);
                reply->setSequenceN(recipient->getSnServer());
                //sent target public key to requester of opening the conversation
                result = SocketManager::send_authenticated_message(recipient->getSocket(), reply,
                                                                   recipient->getSessionKey());
            }
            //request to talk accepted
            if(result){
                //increment sequence number
                recipient->increment_server_sn();
                delete reply;
                NEW(reply,new Message(),"REQUEST_OK allocating message failed")
                iv = CryptoManager::generate_iv();
                IF_MANAGER_FAILED(iv,"REQUEST_OK generating iv failed",0)
                //owner public key
                reply->setSender(recipient->getUserName());
                reply->setType(PEER_PUB_KEY);
                reply->getPayload()->setPubKey(recipient->getPublicKey());
                reply->setIv(iv);
                reply->setSequenceN(sender->getSnServer());
                //sent requester public key to target of the conversation
                result = SocketManager::send_authenticated_message(sender->getSocket(),reply,
                                                                   sender->getSessionKey());
                if(result) sender->increment_server_sn();
                //disconnect target
                else disconnect_client(sender->getSocket(),&client_set,&fd_num);

            } //accepting of request to talk failed
            else{
                //disconnect requester
                disconnect_client(recipient->getSocket(),&client_set,&fd_num);
                //notify sender of REQUEST_OK
                iv = CryptoManager::generate_iv();
                reply->setType(ERROR);
                reply->setErrCode(FORWARD_ACCEPT_FAIL);
                reply->setIv(iv);
                reply->setSequenceN(sender->getSnServer());
                result = SocketManager::send_authenticated_message(sender->getSocket(),
                                                                   reply,sender->getSessionKey());
                IF_MANAGER_FAILED(result,"REQUEST_OK sending forward error failed",0);
                sender->setIsBusy(false);
                recipient->setIsBusy(false);
                session->close_chat(recipient->getUserName(), sender->getUserName());
            }
            break;
        case REQUEST_KO:
            //check authenticity
            result = check_client_message(message);
            if(!result)
                return result;
            sender = session->get_user(username_sender);
            recipient = session->get_user(message->getRecipient());
            if(recipient->isOnline()) {
                iv = CryptoManager::generate_iv();
                //free because they will be replaced
                delete message->getIv();
                delete message->getPayload()->getAuthTag();
                message->setIv(iv);
                message->setSequenceN(recipient->getSnServer());
                result = SocketManager::send_authenticated_message(recipient->getSocket(), message,
                                                                   recipient->getSessionKey());
                //request to talk rejected, now they can arrange other conversations
                recipient->increment_server_sn();
            }
            //in case of errors in rejecting the request to talk the target user does not care to be informed
            recipient->setIsBusy(false);
            sender->setIsBusy(false);
            session->close_chat(recipient->getUserName(), sender->getUserName());
            break;
        case AUTH_PEER_REQUEST:
        case AUTH_PEER_RESPONSE:
        case AUTH_PEER_KEY_EX:
        case AUTH_PEER_KEY_EX_RX:
            //check authenticity
            result = check_client_message(message);
            if(!result)
                return result;
            sender = session->get_user(username_sender);
            recipient = session->get_user(message->getRecipient());
            result = false;
            if(recipient->isOnline()){
                delete message->getIv();
                iv = CryptoManager::generate_iv();
                message->setIv(iv);
                message->setSequenceN(recipient->getSnServer());
                //peer has sent also its authentication tag
                peer_authentication = message->getType() == AUTH_PEER_KEY_EX_RX;
                //delete the current tag it will be replaced
                if(!peer_authentication)
                    delete message->getPayload()->getAuthTag();

                result = SocketManager::send_authenticated_message(recipient->getSocket(), message,
                                                                   recipient->getSessionKey(), peer_authentication);
                recipient->increment_server_sn();
            }
            //TODO SEND ERROR MESSAGE
            break;
        case USERS_LIST:
            result = check_client_message(message);
            if(!result)
                return result;
            online_users = session->get_online_users();
            sender = session->get_user(username_sender);
            result = SocketManager::send_encrypted_message(sender->getSocket(),sender->getSnServer(),
                                                           sender->getSessionKey(),online_users,USERS_LIST_RESPONSE);
            IF_MANAGER_FAILED(result,"sending users list failed",0)
            sender->increment_server_sn();
            break;
        default:
            cerr << "wrong type!!" << endl;
            break;

    }
    //clean messages
    delete message;
    return result;
}

void disconnect_client(int socket,fd_set* client_set,int* fd_num){
    FD_CLR(socket,client_set);
    *fd_num = update_max(*client_set,*fd_num);
    ISLESSTHANZERO(*fd_num,"update_max failed")
    session->disconnect_client(socket);
    close(socket);
    cout << "Client done!!" << endl;
}

int check_client_message(Message* message){
    string username_sender = message->getSender();
    User* sender = session->get_user(username_sender);
    unsigned char* iv;
    unsigned char* aad;
    unsigned char* auth_tag;
    int result = 0;
    size_t len;
    //wrong sequence number
    if(message->getSequenceN() != sender->getSnUser())
        return 0;
    iv = message->getIv();
    len = CryptoManager::message_to_bytes(message,&aad);
    IF_MANAGER_FAILED(len,"check_client_message obtaining aad failed",result);
    if(message->getType() == AUTH_PEER_KEY_EX_RX or message->getType() == DATA)
        auth_tag = message->getServerAuthTag();
    else
        auth_tag = message->getPayload()->getAuthTag();
    result = CryptoManager::verify_auth_data(aad,len,iv,sender->getSessionKey(),
                                             auth_tag);

    IF_MANAGER_FAILED(result,"check_client_message verifying tag",0)
    sender->increment_user_sn();
    delete aad;
    return result;
}

