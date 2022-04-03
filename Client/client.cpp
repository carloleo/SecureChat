
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
    //register function at exit
    ISLESSTHANZERO(atexit(clean_up),"registering function at exit failed")
    //open socket
    memset((void*)&server_address,0,(size_t) sizeof(server_address));
    server_address.sin_family= AF_INET; //kind of socket
    server_address.sin_port = htons(SERVER_PORT); //server port
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");  //server IP
    server_socket = socket(AF_INET,SOCK_STREAM,0);
    ISLESSTHANZERO(server_socket,"Opening socket failed")
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
    getline(cin,username);
    ISNOT(cin,"Ooops! something went wrong")
    trim(username);
    //IDE does not allow to open the prompt
    //reading client pvt key
    FILE* file;
    string filename = (string)  DOCS_DIR + username + "_key.pem" ;
    file = fopen(filename.c_str(),"r");
    ISNOT(file,"opening client private key fail failed")
    pvt_client_key = PEM_read_PrivateKey(file,NULL,NULL,NULL);
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
    //plain text to be sent
    string text;
    string recipient;
    string line;
    //instantiate thread to read messages from server
    std::thread t1 (listener,server_socket,pthread_self());
    cout << "Users online: " << online_users << endl;
    cout << endl;
    while (!done){
        int not_used;
        bool recipient_offline = false;
        Message message;
        int ciphertext_len = 0;
        unsigned  char* ciphertext = nullptr;
        unsigned char* iv;
        unsigned char* tag;
        unsigned char* aad;
        size_t len;
        cout << "Type command" << endl;
        getline(cin,line);
        if(!cin){
            cerr <<"Error getting command" << endl;
            cin.clear();
            continue;
        }
        command = line.substr(0,line.find_first_of(' '));
        trim(command);
        if(!commands.count(command)){
            cerr << "invalid command" << endl;
            continue;
        }
        switch (commands[command]) {
            case TALK:
                m_status.lock();
                if(is_busy){
                    cerr << "You are already attending to a chat" << endl;
                    m_status.unlock();
                    break;
                }
                m_status.unlock();
                recipient.erase();
                cout << "type the recipient's username" << endl;
                getline(cin,recipient);
                if(!cin){
                    cerr << "Error, acquiring the recipient username" << endl;
                    cin.clear();
                    break;
                }
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
                    //send authenticate request
                    not_used = SocketManager::send_authenticated_message(server_socket,&message,
                                                                         sever_session_key);
                    if(not_used) {
                        m_status.lock();
                        server_out_sn += 1;
                        is_busy = true;
                        is_requester = true;
                        m_status.unlock();
                        cout << "Request to talk sent" << endl;
                        cout << endl;
                    }
                    else cerr <<" Error in sending request to talk" << endl;
                }
                break;
            case QUIT:
                m_status.lock();
                if(peer_session_key == nullptr){
                    cerr << "You have not set up any chat" << endl;
                    m_status.unlock();
                    break;
                }
                m_status.unlock();
                message.setType(PEER_QUIT);
                //usernames
                message.setSender(username);
                iv = CryptoManager::generate_iv();
                message.setIv(iv);
                message.setSequenceN(server_out_sn);
                not_used = SocketManager::send_authenticated_message(server_socket,&message,sever_session_key);
                if(not_used) {
                    m_status.lock();
                    is_busy = false;
                    is_requester = false;
                    peer_in_sn = 0;
                    peer_out_sn = 0;
                    server_out_sn += 1;
                    EVP_PKEY_free(peer_pub_key);
                    peer_pub_key = nullptr;
                    destroy_secret(peer_session_key,KEY_LENGTH);
                    peer_session_key = nullptr;
                    m_status.unlock();
                    cout << "Chat has been left"<< endl;
                    cout << endl;
                }
                break;
            case LOGOUT:
                m_status.lock();
                if(peer_session_key != nullptr){
                    cout << "type quit to leave the chat before logout" << endl;
                    m_status.unlock();
                    break;
                }
                m_status.unlock();
                message.setType(CLIENT_DONE);
                message.setSender(username);
                iv = CryptoManager::generate_iv();
                message.setIv(iv);
                message.setSequenceN(server_out_sn);
                SocketManager::send_authenticated_message(server_socket,&message,sever_session_key);
                done = true;
                break;
            case LIST:
                message.setType(USERS_LIST);
                message.setSender(username);
                message.setSequenceN(server_out_sn);
                iv = CryptoManager::generate_iv();
                IF_MANAGER_FAILED(iv,"generating iv failed",1)
                message.setIv(iv);
                //send authenticated request
                not_used = SocketManager::send_authenticated_message(server_socket,&message,sever_session_key);
                if(not_used) {
                    m_status.lock();
                    server_out_sn += 1;
                    m_status.unlock();
                }
                else
                    cerr << "error in sending the request. Try later." << endl;
                break;
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
                    delete request;
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
                    is_busy = false;
                    is_requester = false;
                    server_out_sn += 1;
                    m_status.unlock();
                    delete request;
                    request = nullptr;
                }
                break;
            case SEND:
                m_status.lock();
                if(peer_session_key == nullptr){
                    cerr << "No chat ongoing" << endl;
                    m_status.unlock();
                    cerr << endl;
                    break;
                }
                m_status.unlock();
                cout << "Type the message: " << endl;
                getline(cin,text);
                if(!cin){
                    cerr << "Please re-type the message some error occurred" << endl;
                    cin.clear();
                    break;
                }
                trim(text);
                if(text.length() == 0){
                    cerr << "Cannot sent an empty message" << endl;
                    break;
                }
                if(text.length() > MAX_CHARS){
                    cerr << "Message too long" << endl;
                    break;
                }
                not_used = send_peer_message(server_socket,text, DATA,username,
                                  is_requester ? recipient : peer_username);
                if(not_used){
                    cout << "[" << username << "]: "<< text << endl;
                }
                text.clear();
                break;
            default:
                cerr << "invalid command" << endl;
                break;
        }
        line.erase();
    }
    t1.detach();
    exit(EXIT_SUCCESS);
}


