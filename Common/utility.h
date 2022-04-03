//
// Created by crl on 2/18/22.
//

#ifndef SECURECHAT_UTILITY_H
#define SECURE_CHAT_UTILITY_H
#include <cerrno>
#include <string>
#include <cstring>
#define  SERVER_PORT 8888
#define  MAX_CHARS (size_t) 10000
#define KEY_LENGTH 16
#define ISNOT(var,message) \
            if(!var){            \
                perror(message) ; \
                exit(EXIT_FAILURE);        \
            }
#define ISLESSTHANZERO(var,message) \
            if(var < 0){            \
                perror(message) ; \
                exit(EXIT_FAILURE);        \
            }
#define IF_MANAGER_FAILED(var,message,error_value) \
            if(!var){                              \
              cerr << message << endl;             \
              return error_value;  \
            }
#define NEW(var,new_call,var_name) \
            try{                      \
                var = new_call;                          \
            }catch(std::bad_alloc &e){    \
                std::string err_msg = var_name + (std::string) "bad alloc";                  \
                perror(err_msg.c_str());              \
                exit(EXIT_FAILURE)  ;            \
            }

enum MESSAGE_TYPE{AUTH_REQUEST,AUTH_RESPONSE,AUTH_KEY_EXCHANGE,AUTH_KEY_EXCHANGE_RESPONSE,REQUEST_TO_TALK, REQUEST_OK,
        REQUEST_KO,DATA,ERROR,USERS_LIST,USERS_LIST_RESPONSE, PEER_PUB_KEY,AUTH_PEER_REQUEST,
        AUTH_PEER_RESPONSE,AUTH_PEER_KEY_EX,AUTH_PEER_KEY_EX_RX,PEER_QUIT, CLIENT_DONE};
enum ERROR_CODE{FORWARD_ACCEPT_FAIL,FORWARD_REQUEST_FAIL,PEER_DISCONNECTED};
static inline unsigned char* uint32_to_bytes(uint32_t num){
    unsigned char* bytes;
    NEW(bytes,new unsigned char[sizeof(uint32_t)],"bytes")
    int n = 24;
    for(int i = 0; i < sizeof(uint32_t) ; i++){
        bytes[i] = (unsigned char) (num >> n);
        n -= 8;
    }
    return bytes;
}
static inline void destroy_secret(unsigned char* ptr, size_t size){
#pragma optimize("", off)
    memset(ptr, 0, size);
#pragma optmize("", on)
    delete [] ptr;
}
#endif //SECURECHAT_UTILITY_H
