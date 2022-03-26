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
//cli interface
enum COMMAND{TALK,QUIT,LOGOUT,LIST,ACCEPT,REJECT};
static std::map<std::string ,COMMAND> commands;
void listener(int socket,pthread_t main_tid);
int decrypt_message(Message* data, unsigned char* key, string &message, bool from_user = false);
//messages queue
std::mutex m_lock;
//users online
std::mutex m_online_users;
std::mutex m_status;
std::list<string> users;
std::vector<Message*> messages_queue;
//volatile sig_atomic_t is_talking = 0;
//GLOBAL
bool is_talking = false;
bool is_requester = false;
//chat
EVP_PKEY *peer_pub_key = nullptr;
unsigned char* peer_session_key = nullptr;
uint32_t peer_in_sn = 0;
uint32_t peer_out_sn = 0;
//receive it to server
uint32_t server_in_sn = 0;
//send it to server
uint32_t server_out_sn = 0;
//client private key
EVP_PKEY *pvt_client_key = nullptr;
//session key
unsigned char* sever_session_key = nullptr;
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
    result = read_encrypted_message(server_socket,server_in_sn, online_users,sever_session_key);
    IF_MANAGER_FAILED(result,"reading last handshake message failed",0)
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
    delete eph_pub_key_bytes;


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
    delete to_sign;
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
        aad = uint32_to_bytes(data->getPeerSn());
        aad_size = sizeof(uint32_t);
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
       delete tmp;
    }

    delete data;
    delete aad;
    delete plaintext;
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
    string splitting = " ";
    int index = -1;
    //peer authentication
    uint32_t  nonce;
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
        if(!message){ //TODO termination protocol
            cout << "Disconnecting..." << endl;
            break;
        }
        try{    //TODO: add sequence number check
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
                    m_online_users.lock();
                    online_users.clear();
                    online_users.append(message_text);
                    users.clear();
                    while((index = online_users.find(splitting)) != string::npos){
                        users.push_back(online_users.substr(0,index));
                        //remove last user and splitting char
                        online_users.erase(0,index + splitting.length());
                    }
                    m_online_users.unlock();
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
                        messages_queue.push_back(message);
                        m_lock.unlock();
                        m_status.lock();
                        is_talking = true;
                        m_status.unlock();
                        server_in_sn += 1;
                    }
                    delete aad;
                    break;
                case PEER_PUB_KEY:
                    aad_len = CryptoManager::message_to_bytes(message,&aad);
                    result = CryptoManager::verify_auth_data(aad, aad_len, message->getIv(), sever_session_key,
                                                             message->getPayload()->getAuthTag());
                    if(result){//authenticated data
                        server_in_sn += 1;
                        cout << "PUB key got" << endl;
                        peer_pub_key = message->getPayload()->getPubKey();
                        if(is_requester){
                            iv = CryptoManager::generate_iv();
                            peer_message.setType(AUTH_PEER_REQUEST);
                            peer_message.setIv(iv);
                            peer_message.setSender(username);
                            peer_message.setRecipient(message->getSender());
                            peer_message.setSequenceN(server_out_sn);
                            CryptoManager::generate_nonce(&nonce);
                            peer_message.getPayload()->setNonce(nonce);
                            SocketManager::send_authenticated_message(socket,&peer_message,sever_session_key);
                            server_out_sn += 1;
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
                        is_talking = false;
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
                    //authenticated data
                    if(result) {
                        server_in_sn += 1;
                        eph_pubkey = EVP_PKEY_new();
                        ISNOT(eph_pubkey,"AUTH_PEER_REQUEST allocating ephemeral keys")
                        eph_pvtkey = EVP_PKEY_new();
                        ISNOT(eph_pubkey,"AUTH_PEER_REQUEST allocating ephemeral keys")
                        result = CryptoManager::generate_ephemeral_rsa(&eph_pubkey, &eph_pvtkey);
                        if (result) {
                            signature = CryptoManager::sign_pubKey(eph_pubkey, pvt_client_key,
                                                                   message->getPayload()->getNonce(), &signature_size);
                            if (signature) {
                                nonce = message->getPayload()->getNonce();
                                peer_message.setType(AUTH_PEER_RESPONSE);
                                peer_message.setSequenceN(server_out_sn);
                                peer_message.setSender(message->getRecipient());
                                peer_message.setRecipient(message->getSender());
                                peer_message.getPayload()->setPubKey(eph_pubkey);
                                peer_message.setSignatureLen(signature_size);
                                peer_message.getPayload()->setSignature(signature);
                                iv = CryptoManager::generate_iv();
                                peer_message.setIv(iv);
                                SocketManager::send_authenticated_message(socket, &peer_message, sever_session_key);
                                server_out_sn += 1;
                            }
                        }
                    }
                    break;
                case AUTH_PEER_RESPONSE:
                    aad_len = CryptoManager::message_to_bytes(message,&aad);
                    result = CryptoManager::verify_auth_data(aad, aad_len, message->getIv(), sever_session_key,
                                                             message->getPayload()->getAuthTag());
                    //authenticated data
                    if(result){
                        server_in_sn += 1;
                        signature = message->getPayload()->getSignature();
                        result = CryptoManager::verify_signed_pubKey(message->getPayload()->getPubKey(),nonce,
                                                                     peer_pub_key,signature,message->getSignatureLen());
                        ISNOT(result,"non-authenticated data received")
                        peer_message.setType(AUTH_PEER_KEY_EX);
                        peer_message.setRecipient(message->getSender());
                        peer_message.setSequenceN(server_out_sn);
                        iv = CryptoManager::generate_iv();
                        peer_message.setIv(iv);
                        result = prepare_third_message(message->getPayload()->getPubKey(),&peer_message,true);
                        ISNOT(result,"prepare third message failed")
                        result = SocketManager::send_authenticated_message(socket,&peer_message,sever_session_key);
                        ISNOT(result,"sending third message failed")
                        server_out_sn += 1;
                    }
                    break;
                case AUTH_PEER_KEY_EX:
                    aad_len = CryptoManager::message_to_bytes(message,&aad);
                    result = CryptoManager::verify_auth_data(aad, aad_len, message->getIv(), sever_session_key,
                                                             message->getPayload()->getAuthTag());
                    if(result){
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
                        //peer signature verified
                        if(result){
                            //decrypt master secret  key
                            result = CryptoManager::rsa_decrypt(message->getPayload()->getCiphertext(),message->getCTxtLen(),&plaintext,
                                                                &plain_size,eph_pvtkey);
                            //delete ephemeral keys
                            EVP_PKEY_free(eph_pubkey);
                            EVP_PKEY_free(eph_pvtkey);
                            eph_pubkey = nullptr;
                            eph_pubkey = nullptr;
                            ISNOT(result,"AUTH_PEER_KEY_EX decrypting session key failed")
                            peer_session_key = CryptoManager::compute_session_key(plaintext,plain_size);
                            ISNOT(peer_session_key,"computing session key failed")
                            //destroy master secret
                            destroy_secret(plaintext,plain_size);
                            //send confirmation message
                            iv = CryptoManager::generate_iv();
                            peer_message.setType(AUTH_PEER_KEY_EX_RX);
                            peer_message.setPeerIv(iv);
                            peer_message.setSender(username);
                            peer_message.setRecipient(message->getSender());
                            peer_message.setSequenceN(server_out_sn);
                            peer_message.setPeerSn(peer_out_sn);
                            NEW(auth_tag, new unsigned char[TAG_LEN],"AUTH_PEER_KEY_EX allocating tag failed")
                            NEW(ciphertext, new unsigned char[sizeof(uint32_t) + EVP_CIPHER_block_size(CIPHER)],"AUTH_PEER_KEY_EX allocating ciphertext failed")
                            aad = uint32_to_bytes(peer_out_sn);
                            nonce += 1;
                            ciphertext_len = CryptoManager::gcm_encrypt(uint32_to_bytes(nonce),
                                                                        sizeof(uint32_t),
                                                                        aad,sizeof(uint32_t),
                                                                        peer_session_key, iv,
                                                                        IV_LEN,ciphertext,auth_tag);
                            iv = CryptoManager::generate_iv();
                            peer_message.setIv(iv);
                            peer_message.getPayload()->setAuthTag(auth_tag);
                            peer_message.getPayload()->setCiphertext(ciphertext);
                            peer_message.setCTxtLen(ciphertext_len);
                            SocketManager::send_authenticated_message(socket,&peer_message,sever_session_key,true);
                            peer_out_sn += 1;
                            server_out_sn += 1;
                        }
                    }
                    break;
                case AUTH_PEER_KEY_EX_RX:
                    aad_len = CryptoManager::message_to_bytes(message,&aad);
                    result = CryptoManager::verify_auth_data(aad, aad_len, message->getIv(), sever_session_key,
                                                             message->getServerAuthTag());
                    //authenticated data from server
                    if(result){
                        result = decrypt_message(message,peer_session_key,s, true);
                        cout << "RESULT: " << result << endl;
                        //TODO compare nonce
                        peer_in_sn += 1;
                    }
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
                                is_talking = false;
                                m_status.unlock();
                                break;
                            case FORWARD_REQUEST_FAIL:
                                cerr << "Server unable to forward your request to talk." << endl;
                                m_status.lock();
                                is_talking = false;
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