//
// Created by crl on 2/18/22.
//

#ifndef SECURECHAT_UTILITY_H
#define SECURE_CHAT_UTILITY_H
#include <cerrno>
#include <string>
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

enum MESSAGE_TYPE{AUTH_REQUEST,AUTH_RESPONSE,AUTH_KEY_EXCHANGE,AUTH_KEY_EXCHANGE_RESPONSE,REQUEST_TO_TALK, REQUEST_OK,
        REQUEST_KO,DATA,ERROR};
#endif //SECURECHAT_UTILITY_H
