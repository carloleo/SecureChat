
#include "client_header.h"


//
// Created by crl on 2/19/22.
//
int main(){
    int server_socket;
    int not_used;
    struct sockaddr_in server_address;
    string  command;
    bool done = false;
    Message* request  = nullptr;
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
    commands["talk"] = TALK;
    commands["quit"] = QUIT;
    commands["logout"] = LOGOUT;
    commands["list"] = LIST;
    commands["accept"] = ACCEPT;
    commands["reject"] = REJECT;
    commands["send"] = SEND;
    cout << "type your username: " << endl;
    cin >> username;
    ISNOT(cin,"Ooops! something went wrong")
    trim(username);
    //IDE does not allow to open promt
    string pwd;
    cout << "pwd" << endl;
    cin >> pwd;
    //reading client pvt key
    FILE* file;
    string filename = (string)  CERT_DIR + username + "_key.pem" ;
    file = fopen(filename.c_str(),"r");
    ISNOT(file,"opening client private key fail failed")
    pvt_client_key = PEM_read_PrivateKey(file,NULL,NULL,(void*) pwd.c_str());
    fclose(file);
    ISNOT(pvt_client_key,"reading client pvt key failed")
    not_used = authenticate_to_server(server_socket,username,online_users);
    //increment server sequence number
    server_in_sn += 1;
    if(!not_used){
        cerr << "Authentication failed: cannot proceed!" << endl;
        close(server_socket);
        exit(EXIT_FAILURE);
    }
    //instantiate thread to read messages from server
    std::thread t1 (listener,server_socket,pthread_self());
    cout << "Users online: " << online_users << endl;
    cout << endl;
    while (!done){
        int not_used;
        bool recipient_offline = false;
        string text;
        string recipient;
        Message message;
        int ciphertext_len = 0;
        unsigned  char* ciphertext = nullptr;
        unsigned char* iv;
        unsigned char* tag;
        unsigned char* aad;
        size_t len;
        cout << "Type command" << endl;
        cin >> command;
        ISNOT(cin,"error getting command")
        trim(command);
        if(!commands.count(command)){
            cerr << "invalid command" << endl;
            continue;
        }
        switch (commands[command]) {
            case TALK:
                m_status.lock();
                if(is_talking){
                    cerr << "You are already attending to a chat" << endl;
                    m_status.unlock();
                    break;
                }
                m_status.unlock();
                cout << "type the recipient's username" << endl;
                cin >> recipient;
                ISNOT(cin," ");
                trim(recipient);
                //yourself
                if(username.compare(recipient) == 0){
                    cerr << "cannot open a conversation with yourself" << endl;
                    break;
                }
                //check if recipient is online
                recipient_offline = !is_online(recipient);
                if(recipient_offline) {
                    cerr << "username is not online" << endl;
                    cout << "type 'list' to updated the list" << endl;
                }
                else{
                    message.setType(REQUEST_TO_TALK);
                    message.setSender(username);
                    message.setRecipient(recipient);
                    message.setSequenceN(server_out_sn);
                    iv = CryptoManager::generate_iv();
                    IF_MANAGER_FAILED(iv,"generating iv failed",1)
                    message.setIv(iv);
                    //authenticate request
                    NEW(tag,new unsigned char[TAG_LEN],"allocating tag")
                    size_t len = CryptoManager::message_to_bytes(&message,&aad);
                    not_used = CryptoManager::authenticate_data(aad,
                                                                len,iv,sever_session_key,tag);
                    IF_MANAGER_FAILED(not_used,"Authenticate data failed",1)
                    message.getPayload()->setAuthTag(tag);
                    not_used = SocketManager::send_message(server_socket,&message);
                    IF_MANAGER_FAILED(not_used,"Sending request to talk",1)
                    delete aad;
                    m_status.lock();
                    server_out_sn += 1;
                    is_talking = true;
                    is_requester = true;
                    m_status.unlock();
                    cout << "Request to talk sent" << endl;
                    cout << endl;
                }
                break;
            case QUIT:
                m_status.lock();
                if(!is_talking){
                    cerr << "You are not attending to any chat" << endl;
                    m_status.unlock();
                    break;
                }
                m_status.unlock();
                message.setType(PEER_QUIT);
                //usernames of re
                message.setSender(username);
                iv = CryptoManager::generate_iv();
                message.setIv(iv);
                message.setSequenceN(server_out_sn);
                not_used = SocketManager::send_authenticated_message(server_socket,&message,sever_session_key);
                if(not_used) {
                    m_status.lock();
                    is_talking = false;
                    is_requester = false;
                    peer_in_sn = 0;
                    peer_out_sn = 0;
                    server_out_sn += 1;
                    EVP_PKEY_free(peer_pub_key);
                    peer_pub_key = nullptr;
                    m_status.unlock();
                    cout << "Chat has been left"<< endl;
                    cout << endl;
                }
                break;
            case LOGOUT:
                done = true;
                break;
            case LIST:
                message.setType(USERS_LIST);
                message.setSender(username);
                message.setSequenceN(server_out_sn);
                iv = CryptoManager::generate_iv();
                IF_MANAGER_FAILED(iv,"generating iv failed",1)
                message.setIv(iv);
                //authenticate request
                NEW(tag,new unsigned char[TAG_LEN],"allocating tag")
                len = CryptoManager::message_to_bytes(&message,&aad);
                not_used = CryptoManager::authenticate_data(aad,
                                                            len,iv,sever_session_key,tag);
                IF_MANAGER_FAILED(not_used,"Authenticate data failed",1)
                message.getPayload()->setAuthTag(tag);
                not_used = SocketManager::send_message(server_socket,&message);
                IF_MANAGER_FAILED(not_used,"Sending request to talk",1)
                server_out_sn += 1;
                delete aad;
                break;
                //TODO make a function to send authenticate request
            case ACCEPT:
                m_lock.lock();
                if(!messages_queue.empty())
                    request = messages_queue.back();
                m_lock.unlock();
                if(request == nullptr){
                    cout << "Any pending request to be accepted" << endl;
                    break;
                }
                iv = CryptoManager::generate_iv();
                IF_MANAGER_FAILED(iv,"getting iv failed",1)
                message.setType(REQUEST_OK);
                message.setIv(iv);
                message.setSequenceN(server_out_sn);
                //sender is who received the request to talk
                message.setSender(request->getRecipient());
                //recipient is who sent the request to talk
                message.setRecipient(request->getSender());
                not_used = SocketManager::send_authenticated_message(server_socket,&message,sever_session_key);
                if(!not_used)
                    cerr << "accepting request to talk from: " << request->getSender() << "failed. Try later" << endl;
                else{//request consumed
                    m_lock.lock();
                    messages_queue.pop_back();
                    m_lock.unlock();
                    request = nullptr;
                    m_status.lock();
                    server_out_sn += 1;
                    m_status.unlock();
                    cout << "Request to talk has been accepted" << endl;
                    cout << endl;
                }

                break;
            case REJECT:
                m_lock.lock();
                if(!messages_queue.empty())
                    request = messages_queue.back();
                m_lock.unlock();
                if(request == nullptr){
                    cout << "Any pending request to be rejected" << endl;
                    break;
                }
                iv = CryptoManager::generate_iv();
                IF_MANAGER_FAILED(iv,"getting iv failed",1)
                message.setType(REQUEST_KO);
                message.setIv(iv);
                message.setSequenceN(server_out_sn);
                //sender is who received the request to talk
                message.setSender(request->getRecipient());
                //recipient is who sent the request to talk
                message.setRecipient(request->getSender());
                not_used = SocketManager::send_authenticated_message(server_socket,&message,sever_session_key);
                if(!not_used)
                    cerr << "rejecting request to talk from: " << request->getSender() << "failed. Try later" << endl;
                else{//request consumed
                    m_lock.lock();
                    messages_queue.pop_back();
                    m_lock.unlock();
                    m_status.lock();
                    is_talking = false;
                    is_requester = false;
                    server_out_sn += 1;
                    m_status.unlock();
                    request = nullptr;
                    cout << "Request to talk from has been rejected" << endl;
                    cout << endl;
                }
                break;
            case SEND:
//                if(request == nullptr){
//                    cerr << "No chat ongoing" << endl;
//                    cerr << endl;
//                }
//                cout << "Type the message: " << endl;
//                cin >> text;
//                message.setType(DATA);
//                message.setSender(username);
//                message.setRecipient(is_requester ? recipient : peer_username);
//                iv = CryptoManager::generate_iv();
//                message.setPeerIv(iv);
//                message.setPeerSn(peer_out_sn);
//                //TODO authenticate message and send iv
//                aad = uint32_to_bytes(peer_out_sn);
//                NEW(tag,new unsigned char[TAG_LEN],"allocating tag")
//                NEW(ciphertext, new unsigned char[sizeof(uint32_t) + BLOCK_SIZE],"allocating ciphertext failed")
//                ciphertext_len = CryptoManager::gcm_encrypt((unsigned char*) text.c_str(),
//                                                            text.length(),
//                                                            aad,sizeof(uint32_t),
//                                                            peer_session_key, iv,
//                                                            IV_LEN,ciphertext,tag);
//                ISNOT(ciphertext_len,"encrypting messaged failed")
//                message.setCTxtLen(ciphertext_len);
//                message.getPayload()->setAuthTag(tag);
//                //set iv for the server
//                iv = CryptoManager::generate_iv();
//                //set sn for the server
//                message.setSequenceN(server_out_sn);
//                message.setIv(iv);
//                SocketManager::send_authenticated_message(server_socket,&message,peer_session_key, true);
//                cout << "Message sent" << endl;
//                server_out_sn += 1;
//                peer_out_sn += 1;
                break;
            default:
                cerr << "invalid command" << endl;
                break;
        }
    }
    t1.detach();
    EVP_PKEY_free(pvt_client_key);
    return  0;
}


