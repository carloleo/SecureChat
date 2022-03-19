
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
    if(!not_used){
        cerr << "Authentication failed: cannot proceed!" << endl;
        close(server_socket);
        exit(EXIT_FAILURE);
    }
    cout << "ONLINE USERS" << endl << online_users;
    while (!done){
        cout << "Type command" << endl;
        cin >> command;
        string recipient;
        Message message;
        switch (commands[command]) {
            case TALK:
                cout << "select recipient among online users" << endl;
                cout << online_users << endl;
                cin >> recipient;
                if(online_users.find(recipient) == std::string::npos)
                    cerr <<"wrong username" << endl;
                else{
                    message.setType(REQUEST_TO_TALK);
                    message.setSender(username);
                    message.setRecipient(recipient);
                    message.setSequenceN(server_out_sn);
                    unsigned char* iv;
                    iv = CryptoManager::generate_iv(message.getSequenceN());
                    IF_MANAGER_FAILED(iv,"generating iv failed",1)
                    unsigned char* tag;
                    NEW(tag,new unsigned char[TAG_LEN],"allocating tag")
                    not_used = CryptoManager::authenticate_data((unsigned char*)&server_out_sn,
                                                                sizeof(server_out_sn),iv,sever_session_key,tag);
                    IF_MANAGER_FAILED(not_used,"Authenticate data failed",1)
                    message.getPayload()->setAuthTag(tag);
                    not_used = SocketManager::send_message(server_socket,&message);
                    IF_MANAGER_FAILED(not_used,"Sending request to talk",1)
                    server_out_sn += 1;


                }
                break;
            case QUIT:
                break;
            case LOGOUT:
                done = true;
                break;
            default:
                cerr << "invalid command" << endl;
        }
    }
    close(server_socket);
    EVP_PKEY_free(pvt_client_key);
    return  0;
}


