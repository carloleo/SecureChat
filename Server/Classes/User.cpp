//
// Created by crl on 3/1/22.
//


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
    if(session_key)
        destroy_secret(session_key,KEY_LENGTH);

}
User::~User() {
    deleteSessionKey();
    EVP_PKEY_free(public_key);
}

void User::setSocket(int socket) {
    User::socket = socket;
}

void User::setPublicKey(EVP_PKEY *publicKey) {
    public_key = publicKey;
}

int User::getSocket() const {
    return socket;
}

EVP_PKEY *User::getPublicKey() const {
    return public_key;
}

uint32_t User::getSnUser() const {
    return sn_user;
}

uint32_t User::getSnServer() const {
    return sn_server;
}

void User::setSnUser(uint32_t snUser) {
    sn_user = snUser;
}

void User::setSnServer(uint32_t snServer) {
    sn_server = snServer;
}
