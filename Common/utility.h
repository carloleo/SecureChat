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
#define MAX_USERNAME 32
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
        REQUEST_KO,DATA,ERROR};
static inline unsigned char* uint32_to_bytes(uint32_t num){
    unsigned char* bytes;
    NEW(bytes,new unsigned char[4],"bytes")
    int n = 24;
    for(int i = 0; i < 4 ; i++){
        bytes[i] = num >> n;
        n -= 8;
    }
    return bytes;
}
static inline void destroy_secret(unsigned char* ptr, size_t size){
#pragma optimize("", off)
    memset(ptr, 0, size);
#pragma optmize("", on)
    delete ptr;
}
#endif //SECURECHAT_UTILITY_H
