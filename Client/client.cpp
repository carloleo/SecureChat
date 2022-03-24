
#include "client_header.h"


//
// Created by crl on 2/19/22.
//
int main(){
    int server_socket;
    int not_used;
    struct sockaddr_in server_address;
    string  command;
    string online_users;
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
    commands["talk"] = TALK;
    commands["quit"] = QUIT;
    commands["logout"] = LOGOUT;
    commands["list"] = LIST;
    cout << "type your username: " << endl;
    cin >> username;
    ISNOT(cin,"Ooops! something went wrong")
    cout << "authentication in progress..." << endl;
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
    //install handler and instantiate thread to read messages from server
    //signal(SIGUSR1,handler);
    std::thread t1 (listener,server_socket,pthread_self());

    while (!done){
        int not_used;
        string recipient;
        Message message;
        Message* reply;
        unsigned char* iv;
        unsigned char* tag;
        unsigned char* aad;
        size_t len;
        cout << "Type command" << endl;
        cin >> command;
        switch (commands[command]) {
            case TALK:
                cout << "select the recipient among online users" << endl;
                cout << online_users << endl;
                cin >> recipient;
                if(online_users.find(recipient) == std::string::npos)
                    cerr <<"wrong username" << endl;
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
                    server_out_sn += 1;
                    delete aad;
                }
                break;
            case QUIT:
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
            default:
                cerr << "invalid command" << endl;
                break;
        }
    }
    t1.detach();
    EVP_PKEY_free(pvt_client_key);
    return  0;
}


