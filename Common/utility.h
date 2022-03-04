//
// Created by crl on 2/18/22.
//

#ifndef SECURECHAT_UTILITY_H
#define SECURE_CHAT_UTILITY_H
#include <cerrno>
#include <string>
#define  ERROR 1
#define  SERVER_PORT 8888
#define  MAX_CHARS (size_t) 10000
#define ISNOT(var,message) \
            if(!var){            \
                perror(message) ; \
                exit(ERROR);        \
            }
#define ISLESSTHANZERO(var,message) \
            if(var < 0){            \
                perror(message) ; \
                exit(ERROR);        \
            }
enum MESSAGE_TYPE{AUTH_REQUEST,AUTH_RESPONSE,AUTH_KEY_EXCHANGE,AUTH_KEY_EXCHANGE_RESPONSE,REQUEST_TO_TALK, REQUEST_OK, REQUEST_KO,DATA};
#endif //SECURECHAT_UTILITY_H
