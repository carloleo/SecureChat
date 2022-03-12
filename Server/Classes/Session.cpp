//
// Created by crl on 3/1/22.
//

#include "Session.h"

User* Session::get_user(string username) {
    return users.at(username);
}

void Session::add_user(User* user) {
    string username = user->getUserName();
    users[username] = user;
}

void Session::change_status(string username, bool is_online) {
    users.at(username)->setIsOnline(is_online);
}

Session::~Session(){
    auto usr = users.begin();
    while(usr != users.end()){
        delete usr->second;
        usr++;
    }
    users.clear();
    if(server_pvt_key)
        EVP_PKEY_free(server_pvt_key);

    auto eph_key = ephemeral_keys.begin();

    while(eph_key != ephemeral_keys.end()){
        EVP_PKEY_free(eph_key->second.first);
        EVP_PKEY_free(eph_key->second.second);
        eph_key++;
    }
}

bool Session::is_registered(std::string username){
    return users.find(username) == users.end();
}

void Session::add_ephemeral_keys(string username,pair<EVP_PKEY*,EVP_PKEY*> eph_keys){
    ephemeral_keys[username] = eph_keys;
}
pair<EVP_PKEY*,EVP_PKEY*> Session::get_ephemeral_keys(std::string username){
    return ephemeral_keys.at(username);
}

void Session::setServerPvtKey(EVP_PKEY *serverPvtKey) {
    server_pvt_key = serverPvtKey;
}
