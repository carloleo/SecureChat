#include <iostream>
#include "../Utility/utility.h"
#include <netinet/in.h>
#include  <unistd.h>
#include <cstring>
using namespace std;
int update_max(fd_set set,int fd_max);
int main() {
    int master_socket;
    //int client_sockets[MAX_CONN];
    //client's socket
    int fd_c = -1;
    size_t n_byte_read;
    int not_used;
    fd_set client_set;
    fd_set  read_set;
    //socket address
    struct sockaddr_in address;
    char buff [MAX_CHARS + 1];

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
        not_used = select(fd_num + 1,&read_set, nullptr, nullptr, nullptr);
        ISLESSTHANZERO(not_used,"select failedS")
        //find the ready socket
        for(int fd = 3; fd <= fd_num;fd ++){
            if(FD_ISSET(fd,&read_set)){
                if(fd == master_socket){
                    fd_c = accept(fd, nullptr,nullptr);
                    FD_SET(fd_c,&client_set);
                    if(fd_c > fd_num ) fd_num = fd_c;
                } else{
                    n_byte_read = read(fd_c,buff,MAX_CHARS);
                    if(n_byte_read == 0){ //client done
                        FD_CLR(fd,&client_set);
                        fd_num = update_max(client_set,fd_num);
                        ISLESSTHANZERO(fd_num,"update_max failed")
                        close(fd);
                        cout << "Client done!!" << endl;
                    }
                    else{
                        cout <<"read: " <<  buff << endl;
                        string reply = "I'm doing so well!! se you later";
                        size_t size = reply.length();
                        size_t tmp = write(fd,reply.c_str(),size);
                        cout << "Replied " << tmp << endl;
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
