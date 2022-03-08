//
// Created by crl on 3/1/22.
//

#include <cstring>
#include "User.h"
#include "../Common/utility.h"
const std::string &User::getUserName() const {
    return user_name;
}

unsigned char *User::getSessionKey() const {
    return session_key;
}

void User::setUserName(const std::string &userName) {
    user_name = userName;
}

void User::setSessionKey(unsigned char* sessionKey) {
    session_key = sessionKey;
}

void User::setIsOnline(bool isOnline) {
    is_online = isOnline;
}

bool User::isOnline() const {
    return is_online;
}

void User::deleteSessionKey() const{
    if(session_key) {
#pragma optimize("", off)
        memset(session_key, 0, KEY_LENGTH);
#pragma optmize("", on)
        free(session_key);
    }
}
User::~User() {
    deleteSessionKey();
}
