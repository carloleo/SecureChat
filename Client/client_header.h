#include <netinet/in.h>
#include <cstring>
#include <arpa/inet.h>
#include  <unistd.h>
#include <iostream>
#include <map>
#include <mutex>
#include <vector>
#include <csignal>
#include <thread>
#include <list>
#include "../Managers/managers.h"
#define CERT_DIR (string )"../Client/Certs/"
#define CA_CERT (string) "CA.pem"
#define CA_CRL "CA_crl.pem"
using namespace std;
using namespace Managers;
void usage();
//functions
int authenticate_to_server(int server_socket,string username,string &online_users);
int verify_cert(X509*);
int prepare_third_message(EVP_PKEY*,Message*,bool for_peer = false);
int read_encrypted_message(int socket,uint32_t sequence_number,string &message, unsigned char* key);
inline std::string trim(std::string& str);
bool  is_online(string username);
void update_users_list(string text_list);
//cli interface
enum COMMAND{TALK,QUIT,LOGOUT,LIST,ACCEPT,REJECT,SEND};
static std::map<std::string ,COMMAND> commands;
void listener(int socket,pthread_t main_tid);
int decrypt_message(Message* data, unsigned char* key, string &message, bool from_user = false);
int prepare_peer_aad(Message* message, unsigned char** aad);
int send_peer_message(int socket, string text, MESSAGE_TYPE messageType, string sender, string recipient);
//messages queue
std::mutex m_lock;
//users online
std::mutex m_online_users;
std::mutex m_status;
std::list<string> users;
std::list<Message*> messages_queue;
//volatile sig_atomic_t is_talking = 0;
//GLOBAL
//client private key
EVP_PKEY *pvt_client_key = nullptr;
//session key
unsigned char* sever_session_key = nullptr;

//chat
EVP_PKEY *peer_pub_key = nullptr;
unsigned char* peer_session_key = nullptr;
//CLIENT STATUS
uint32_t peer_in_sn = 0;
uint32_t peer_out_sn = 0;
string peer_username;
bool is_busy= false;
bool is_requester = false;
//receive it to server, after thread instantiation it is only managed by the listener
uint32_t server_in_sn = 0;
//send it to server
uint32_t server_out_sn = 0;

string username;
string online_users;


int  verify_cert(X509* cert){
    X509* ca_cert = CryptoManager::open_certificate(CERT_DIR + CA_CERT);
    ISNOT(ca_cert,"opening CA certificate failed")
    X509_CRL* ca_crl = CryptoManager::open_crl(CERT_DIR + CA_CRL);
    ISNOT(ca_crl,"opening CA_crl failed")
    int result = CryptoManager::verify_cert(ca_cert,ca_crl,cert);
    X509_free(ca_cert);
    X509_CRL_free(ca_crl);
    return result;
}

int authenticate_to_server(int server_socket, string username, string &online_users){
    int result;
    Message *second_message;
    Message* first_message;
    string text_list;
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
    result = verify_cert(server_cert);
    EVP_PKEY* server_pub_key = X509_get_pubkey(server_cert);

    EVP_PKEY* eph_pub_key = second_message->getPayload()->getPubKey();
    unsigned char* signature = second_message->getPayload()->getSignature();
    uint32_t signature_length = second_message->getSignatureLen();
    //verify signature on ephemeral public key
    result = CryptoManager::verify_signed_pubKey(eph_pub_key,nonce,server_pub_key,signature,
                                                 signature_length);
    IF_MANAGER_FAILED(result,"verifying ephemeral signed public key failed",0)
    //delete second_message;
    //send third message
    Message* third_message;
    NEW(third_message,new Message(),"third message");
    third_message->setType(AUTH_KEY_EXCHANGE);
    result = prepare_third_message(eph_pub_key,third_message);
    IF_MANAGER_FAILED(result,"prepare third message failed",0)
    result = SocketManager::send_message(server_socket,third_message);
    IF_MANAGER_FAILED(result,"sending third message failed",0)
    result = read_encrypted_message(server_socket,server_in_sn, text_list,sever_session_key);
    IF_MANAGER_FAILED(result,"reading last handshake message failed",0)
    //build users list
    update_users_list(text_list);
    delete second_message;
    delete third_message;
    X509_free(server_cert);
    return result;

}
int prepare_third_message(EVP_PKEY* eph_pub_key,Message* msg, bool for_peer){
    int result;
    //session key
    unsigned char* master_secret;
    unsigned char* session_key = nullptr;
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
    delete [] eph_pub_key_bytes;


    //sign
    unsigned char* signature;
    uint32_t signature_len;
    uint32_t plain_size = encrypted_ms_size + eph_pub_key_bytes_size;
    signature = CryptoManager::sign(to_sign,plain_size,pvt_client_key,
                                    &signature_len);
    IF_MANAGER_FAILED(signature_len,"signing to_sign failed",0)
    msg->setSender(username);
    //set encrypted session key
    msg->setCTxtLen(encrypted_ms_size);
    msg->getPayload()->setCiphertext(encrypted_master_secret);
    //set signature
    msg->setSignatureLen(signature_len);
    msg->getPayload()->setSignature(signature);
    //generate session key
    session_key = CryptoManager::compute_session_key(master_secret,KEY_LENGTH);
    if(for_peer)
        peer_session_key = session_key;
    else
        sever_session_key = session_key;
    IF_MANAGER_FAILED(sever_session_key,"generating session key failed",0)
    destroy_secret(master_secret,KEY_LENGTH);
    delete [] to_sign;
    return 1;
}
int read_encrypted_message(int socket,uint32_t sequence_number,string &message, unsigned  char* key){
    Message* data = SocketManager::read_message(socket);
    //if not expected sequence number return: reply attack
    if(sequence_number != data->getSequenceN())
        return 0;
    int result;
    result = decrypt_message(data, key, message);
    return result;
}

int decrypt_message(Message* data, unsigned char* key, string &message,bool from_user){
    unsigned char* plaintext;
    unsigned char* aad;
    size_t aad_size;
    //get additional authentication data
    if(from_user){
        //TODO call prepeare_peer_aad
        aad_size = prepare_peer_aad(data,&aad);
    }
    else{
        aad_size = CryptoManager::message_to_bytes(data,&aad);
    }
    int pt_len;
    NEW(plaintext, new unsigned  char[data->getCTxtLen()],"plaintext")
    pt_len = CryptoManager::gcm_decrypt(data->getPayload()->getCiphertext(),data->getCTxtLen(),
                                        aad,aad_size, data->getPayload()->getAuthTag(),
                                        key,from_user ? data->getPeerIv() : data->getIv(),IV_LEN,plaintext);
    //message authenticated
    if(pt_len > 0) {
       char* tmp;
       //format the string
       NEW(tmp, new char[pt_len + 1],"decrypt_message allocating tmp buffer failed");
       memmove(tmp,plaintext,pt_len);
       tmp[pt_len] = '\0';
       message.append(tmp);
       delete [] tmp;
    }

    delete data;
    delete [] aad;
    delete [] plaintext;
    return pt_len > 0;

}
//TODO: peer to peer authentication and managing messages
void listener(int socket,pthread_t main_tid){
    Message* message;
    int result = 0;
    unsigned char *aad = nullptr;
    unsigned char *signature = nullptr;
    uint32_t  signature_size = 0;
    size_t aad_len = 0;
    int index = -1;
    //peer authentication
    uint32_t  nonce;
    uint32_t inc_none;
    string conf_message;
    EVP_PKEY* eph_pubkey = nullptr;
    unsigned char* eph_pubkey_bytes = nullptr;
    uint32_t  eph_pub_key_bytes_size = 0;
    unsigned char* to_verify = nullptr;
    unsigned char* plaintext = nullptr;
    unsigned char* iv = nullptr;
    unsigned char* auth_tag = nullptr;
    unsigned char* ciphertext = nullptr;
    uint32_t ciphertext_len = 0;
    size_t plain_size = 0;
    EVP_PKEY* eph_pvtkey = nullptr;
    while(true){
        Message peer_message;
        string message_text;
        message = SocketManager::read_message(socket);
        string s;
        string tmp;
        if(!message){ //TODO termination protocol
            cout << "Disconnecting..." << endl;
            break;
        }
        try{
            cerr << "SN " << message->getSequenceN() << server_in_sn << endl;
            if(message->getSequenceN() != server_in_sn){
                cerr << "Fatal: received a replayed message" << endl;
                exit(EXIT_FAILURE);
            }
            switch (message->getType()) {
                case USERS_LIST_RESPONSE:
                    result = decrypt_message(message, sever_session_key, message_text);
                    if(!result){
                        cerr << "Decryption went wrong !" << endl;
                        exit(EXIT_FAILURE);

                    }
                    cout << "USERS LIST" << endl;
                    cout << message_text << endl;
                    //update users online list
                    update_users_list(message_text);
                    server_in_sn += 1;
                    break;
                case REQUEST_TO_TALK:
                    aad_len = CryptoManager::message_to_bytes(message,&aad);
                    result = CryptoManager::verify_auth_data(aad, aad_len, message->getIv(), sever_session_key,
                                                             message->getPayload()->getAuthTag());
                    if(result) {
                        cout << "You have just received a REQUEST TO TALK form: " << message->getSender() << endl;
                        cout << "to accept type 'accept', to reject type 'reject' " << endl;
                        m_lock.lock();
                        messages_queue.push_front(message);
                        m_lock.unlock();
                        m_status.lock();
                        is_busy = true;
                        m_status.unlock();
                        server_in_sn += 1;
                        peer_username = message->getSender();
                    }
                    delete [] aad;
                    break;
                case PEER_PUB_KEY:
                    aad_len = CryptoManager::message_to_bytes(message,&aad);
                    result = CryptoManager::verify_auth_data(aad, aad_len, message->getIv(), sever_session_key,
                                                             message->getPayload()->getAuthTag());
                    if(result){//authenticated data
                        server_in_sn += 1;
                        peer_pub_key = message->getPayload()->getPubKey();
                        if(is_requester){
                            iv = CryptoManager::generate_iv();
                            peer_message.setType(AUTH_PEER_REQUEST);
                            peer_message.setIv(iv);
                            peer_message.setSender(username);
                            peer_message.setRecipient(message->getSender());
                            m_status.lock();
                            peer_message.setSequenceN(server_out_sn);
                            m_status.unlock();
                            CryptoManager::generate_nonce(&nonce);
                            peer_message.getPayload()->setNonce(nonce);
                            SocketManager::send_authenticated_message(socket,&peer_message,sever_session_key);
                            m_status.lock();
                            server_out_sn += 1;
                            m_status.unlock();
                        }

                    }
                    else{
                        cerr << "Fatal authentication error" << endl;
                        exit(EXIT_FAILURE);
                    }
                    break;
                case REQUEST_KO:
                    aad_len = CryptoManager::message_to_bytes(message,&aad);
                    result = CryptoManager::verify_auth_data(aad, aad_len, message->getIv(), sever_session_key,
                                                             message->getPayload()->getAuthTag());
                    if(result){//authenticated data
                        server_in_sn += 1;
                        cout << message->getSender() << " rejected your request to talk" << endl;
                        m_status.lock();
                        is_busy = false;
                        is_requester = false;
                        m_status.unlock();
                    }
                    else {
                        cerr << "Fatal authentication error" << endl;
                        exit(EXIT_FAILURE);
                    }
                    break;
                case AUTH_PEER_REQUEST:
                    aad_len = CryptoManager::message_to_bytes(message,&aad);
                    result = CryptoManager::verify_auth_data(aad, aad_len, message->getIv(), sever_session_key,
                                                             message->getPayload()->getAuthTag());

                    if(!result){
                        cerr << "Fatal authentication error" << endl;
                        exit(EXIT_FAILURE);
                    }
                    //authenticated data
                    server_in_sn += 1;
                    eph_pubkey = EVP_PKEY_new();
                    ISNOT(eph_pubkey,"AUTH_PEER_REQUEST allocating ephemeral keys")
                    eph_pvtkey = EVP_PKEY_new();
                    ISNOT(eph_pubkey,"AUTH_PEER_REQUEST allocating ephemeral keys")
                    result = CryptoManager::generate_ephemeral_rsa(&eph_pubkey, &eph_pvtkey);
                    ISNOT(result,"AUTH_PEER_REQUEST generating ephemeral keys failed")
                    signature = CryptoManager::sign_pubKey(eph_pubkey, pvt_client_key,
                                                               message->getPayload()->getNonce(), &signature_size);
                    ISNOT(signature,"AUTH_PEER_REQUEST signing ephemeral key failed")
                    //save nonce to complete peer authentication
                    nonce = message->getPayload()->getNonce();
                    peer_message.setType(AUTH_PEER_RESPONSE);
                    m_status.lock();
                    peer_message.setSequenceN(server_out_sn);
                    m_status.unlock();
                    peer_message.setSender(message->getRecipient());
                    peer_message.setRecipient(message->getSender());
                    peer_message.getPayload()->setPubKey(eph_pubkey);
                    peer_message.setSignatureLen(signature_size);
                    peer_message.getPayload()->setSignature(signature);
                    iv = CryptoManager::generate_iv();
                    peer_message.setIv(iv);
                    result = SocketManager::send_authenticated_message(socket, &peer_message, sever_session_key);
                    ISNOT(result,"AUTH_PEER_REQUEST sending message failed ")
                    m_status.lock();
                    server_out_sn += 1;
                    m_status.unlock();
                    break;
                case AUTH_PEER_RESPONSE:
                    aad_len = CryptoManager::message_to_bytes(message,&aad);
                    result = CryptoManager::verify_auth_data(aad, aad_len, message->getIv(), sever_session_key,
                                                             message->getPayload()->getAuthTag());
                    if(!result){
                        cerr << "Fatal authentication error" << endl;
                        exit(EXIT_FAILURE);
                    }
                    //authenticated data
                    server_in_sn += 1;
                    signature = message->getPayload()->getSignature();
                    result = CryptoManager::verify_signed_pubKey(message->getPayload()->getPubKey(),nonce,
                                                                 peer_pub_key,signature,message->getSignatureLen());
                    if(!result){
                        cerr << "Fatal non-authenticated ephemeral public key" << endl;
                        exit(EXIT_FAILURE);
                    }
                    peer_message.setType(AUTH_PEER_KEY_EX);
                    peer_message.setRecipient(message->getSender());
                    m_status.lock();
                    peer_message.setSequenceN(server_out_sn);
                    m_status.unlock();
                    iv = CryptoManager::generate_iv();
                    peer_message.setIv(iv);
                    result = prepare_third_message(message->getPayload()->getPubKey(),&peer_message,true);
                    ISNOT(result,"AUTH_PEER_RESPONSE preparing third message failed")
                    result = SocketManager::send_authenticated_message(socket,&peer_message,sever_session_key);
                    ISNOT(result,"AUTH_PEER_RESPONSE sending third message failed")
                    m_status.lock();
                    server_out_sn += 1;
                    m_status.unlock();
                    break;
                case AUTH_PEER_KEY_EX:
                    aad_len = CryptoManager::message_to_bytes(message,&aad);
                    result = CryptoManager::verify_auth_data(aad, aad_len, message->getIv(), sever_session_key,
                                                             message->getPayload()->getAuthTag());
                    if(!result){
                        cerr << "Fatal authentication error" << endl;
                        exit(EXIT_FAILURE);
                    }
                    //authenticated data
                    server_in_sn += 1;
                    CryptoManager::pkey_to_bytes(eph_pubkey,&eph_pubkey_bytes,&eph_pub_key_bytes_size);
                    NEW(to_verify, new unsigned char[eph_pub_key_bytes_size + message->getSignatureLen()],
                        "AUTH_PEER_KEY_EX allocating to_verify failed")
                    //copy the encrypted session key
                    memmove(to_verify,message->getPayload()->getCiphertext(),message->getCTxtLen());
                    //move on pointer to put the rest
                    memmove(to_verify + message->getCTxtLen() ,eph_pubkey_bytes,eph_pub_key_bytes_size);
                    delete eph_pubkey_bytes;
                    eph_pubkey_bytes = nullptr;
                    plain_size = eph_pub_key_bytes_size + message->getCTxtLen();
                    result = CryptoManager::verify_signature(signature,signature_size,to_verify, plain_size,
                                                             peer_pub_key);
                    if(!result){
                        cerr << "Fatal authentication error" << endl;
                        exit(EXIT_FAILURE);
                    }
                    //peer signature verified
                    //decrypt master secret  key
                    result = CryptoManager::rsa_decrypt(message->getPayload()->getCiphertext(),message->getCTxtLen(),&plaintext,
                                                        &plain_size,eph_pvtkey);
                    if(!result){
                        cerr << "Fatal master secret decryption failed " << endl;
                        exit(EXIT_FAILURE);
                    }
                    //delete ephemeral keys
                    EVP_PKEY_free(eph_pubkey);
                    EVP_PKEY_free(eph_pvtkey);
                    eph_pubkey = nullptr;
                    eph_pubkey = nullptr;
                    peer_session_key = CryptoManager::compute_session_key(plaintext,plain_size);
                    ISNOT(peer_session_key,"computing session key failed")
                    //destroy master secret
                    destroy_secret(plaintext,plain_size);
                    //send confirmation message
                    nonce += 1;
                    conf_message = to_string(nonce).c_str();
                    result = send_peer_message(socket,conf_message,AUTH_PEER_KEY_EX_RX,username,
                                               message->getSender());
                    ISNOT(result,"ERROR during peer authentication")
                    conf_message.erase();
                    break;
                case AUTH_PEER_KEY_EX_RX:
                    aad_len = CryptoManager::message_to_bytes(message,&aad);
                    result = CryptoManager::verify_auth_data(aad, aad_len, message->getIv(), sever_session_key,
                                                             message->getServerAuthTag());
                    if(!result){
                        cerr << "Fatal authentication error" << endl;
                        exit(EXIT_FAILURE);
                    }

                    //authenticated data from server
                    server_in_sn += 1;
                    m_status.lock();
                    if(peer_in_sn != message->getPeerSn()){
                        cerr << "Fatal: received a replayed peer message" << endl;
                        m_status.unlock();
                        exit(EXIT_FAILURE);
                    }
                    m_status.unlock();
                    tmp = message->getSender();
                    result = decrypt_message(message,peer_session_key,s, true);
                    if(!result){
                        cerr << "Fata authentication error" << endl;
                        exit(EXIT_FAILURE);
                    }
                    inc_none = stoul(s.c_str(), nullptr,0);
                    if((nonce + 1) != inc_none){
                        cerr << "Fatal: unexpected confirmation message " << endl;
                        exit(EXIT_FAILURE);
                    }
                    m_status.lock();
                    peer_in_sn += 1;
                    m_status.unlock();
                    cout << "Chat with " << tmp << " started" << endl;
                    break;
                case DATA:
                    aad_len = CryptoManager::message_to_bytes(message,&aad);
                    result = CryptoManager::verify_auth_data(aad, aad_len, message->getIv(), sever_session_key,
                                                             message->getServerAuthTag());
                    if(!result){
                        cerr << "Fatal authentication error" << endl;
                        exit(EXIT_FAILURE);
                    }
                    server_in_sn += 1;
                    m_status.lock();
                    if(peer_in_sn != message->getPeerSn()){
                        cerr << "Fatal: received a replayed peer message" << endl;
                        m_status.unlock();
                        exit(EXIT_FAILURE);
                    }
                    tmp = message->getSender();
                    result = decrypt_message(message,peer_session_key,s, true);
                    if(!result){
                        cerr << "Fata authentication error" << endl;
                        exit(EXIT_FAILURE);
                    }
                    peer_in_sn += 1;
                    m_status.unlock();
                    cout << "[" << tmp << "]: " << s << endl;
                    s.clear();
                    break;
                case ERROR:
                    aad_len = CryptoManager::message_to_bytes(message,&aad);
                    result = CryptoManager::verify_auth_data(aad, aad_len, message->getIv(), sever_session_key,
                                                             message->getPayload()->getAuthTag());
                    if(result){
                        server_in_sn += 1;
                        switch (message -> getErrCode()){
                            case FORWARD_ACCEPT_FAIL:
                                cerr << "Server unable to accept the request to talk. The request has been nullified" << endl;
                                m_status.lock();
                                is_busy = false;
                                m_status.unlock();
                                break;
                            case FORWARD_REQUEST_FAIL:
                                cerr << "Server unable to forward your request to talk." << endl;
                                m_status.lock();
                                is_busy = false;
                                is_requester = false;
                                m_status.unlock();
                                break;
                            case PEER_DISCONNECTED:
                                cerr << "Peer disconnected. Chat terminated" << endl;
                                m_lock.lock();
                                //in case disconnected before sending a response S
                                if(!messages_queue.empty())
                                    messages_queue.pop_back();
                                m_lock.unlock();
                                m_status.lock();
                                is_busy = false;
                                EVP_PKEY_free(peer_pub_key);
                                peer_pub_key = nullptr;
                                if(peer_session_key != nullptr) {
                                    destroy_secret(peer_session_key, KEY_LENGTH);
                                    peer_session_key = nullptr;
                                }
                                peer_out_sn = 0;
                                peer_in_sn = 0;
                                is_requester = false;
                                m_status.unlock();
                                break;
                            default:
                                break;
                        }
                    }
                    break;
                default:
                    break;
            }
        }
        catch (bad_alloc &e){
            cerr << "Process ends because of it gets out of memory" << endl;
            exit(EXIT_SUCCESS);
        }
        catch (...){
            m_lock.unlock();
        }
    }
    close(socket);
    pthread_exit(nullptr);
}

inline std::string trim(std::string& str){
    str.erase(str.find_last_not_of(' ')+1);         //suffixing spaces
    str.erase(0, str.find_first_not_of(' '));     //prefixing spaces
    return str;
}

bool is_online(string username){
    m_online_users.lock();
    auto it = users.begin();
    bool found = false;
    while(!found && it != users.end()) {
        found = username.compare(*it) == 0;
        it++;
    }
    m_online_users.unlock();
    return found;
}

void update_users_list(string message_text){
    string splitting = " ";
    int index = -1;
    m_online_users.lock();
    online_users.clear();
    online_users.append(message_text);
    users.clear();
    while((index = online_users.find(splitting)) != string::npos){
        users.push_back(online_users.substr(0,index));
        //remove last user and splitting char
        online_users.erase(0,index + splitting.length());
    }
    online_users.append(message_text);
    m_online_users.unlock();
}

int prepare_peer_aad(Message* message, unsigned char** aad){
    BIO* bio = BIO_new(BIO_s_mem());
    size_t len;
    int not_used;
    unsigned char* sn =  uint32_to_bytes(message->getPeerSn());
    if(!bio){
        delete sn;
        return 0;
    }
    not_used = BIO_write(bio, (const char*) sn, sizeof(uint32_t));
    delete [] sn;
    if(!not_used)
        return 0;
    not_used = BIO_write(bio, (const char*) message->getPeerIv(), IV_LEN);
    if(!not_used)
        return 0;
    len = BIO_pending(bio);
    NEW(*aad, new unsigned char[len],"prepare_peer_aad allocating aad failed")
    not_used = BIO_read(bio,*aad,len);
    return not_used > 0 ? len : 0;
}
int send_peer_message(int socket, string text, MESSAGE_TYPE messageType, string sender, string recipient){
    Message message;
    unsigned char* iv = nullptr;
    unsigned char* aad = nullptr;
    unsigned char* ciphertext = nullptr;
    unsigned char* auth_tag = nullptr;
    int ciphertext_len = -1;
    int aad_len = -1;
    int result = 0;
    int to_allocate = -1;
    message.setType(messageType);
    iv = CryptoManager::generate_iv();
    if(!iv)
        return 0;
    message.setPeerIv(iv);
    message.setSender(sender);
    message.setRecipient(recipient);
    m_status.lock();
    message.setPeerSn(peer_out_sn);
    aad_len = prepare_peer_aad(&message,&aad);
    if(!aad_len){
        m_status.unlock();
        return 0;
    }
    NEW(auth_tag, new unsigned char[TAG_LEN],"AUTH_PEER_KEY_EX allocating tag failed")
    to_allocate = text.length() + BLOCK_SIZE;
    NEW(ciphertext, new unsigned char[to_allocate],"AUTH_PEER_KEY_EX allocating ciphertext failed")
    ciphertext_len = CryptoManager::gcm_encrypt((unsigned char*) text.c_str(),
                                                text.length(),
                                                aad,aad_len,
                                                peer_session_key, iv,
                                                IV_LEN,ciphertext,auth_tag);
    if(!ciphertext_len){
        m_status.unlock();
        return 0;
    }
    delete [] aad;
    message.getPayload()->setCiphertext(ciphertext);
    message.setCTxtLen(ciphertext_len);
    message.getPayload()->setAuthTag(auth_tag);
    //set server data
    message.setSequenceN(server_out_sn);
    iv = CryptoManager::generate_iv();
    if(!iv){
        m_status.unlock();
        return 0;
    }
    message.setIv(iv);
    result = SocketManager::send_authenticated_message(socket,&message,sever_session_key,true);
    ISNOT(result, "send_peer_message sending message failed")
    server_out_sn += 1;
    peer_out_sn += 1;
    m_status.unlock();
    return  1;
}