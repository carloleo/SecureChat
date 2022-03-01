//
// Created by crl on 3/1/22.
//

#include "User.h"

const string &User::getUserName() const {
    return user_name;
}

char *User::getSessionKey() const {
    return session_key;
}

void User::setUserName(const string &userName) {
    user_name = userName;
}

void User::setSessionKey(char *sessionKey) {
    session_key = sessionKey;
}

void User::setIsOnline(bool isOnline) {
    is_online = isOnline;
}

bool User::isOnline() const {
    return is_online;
}
