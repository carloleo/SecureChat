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
    return users.find(username) != users.end();
}

void Session::add_ephemeral_keys(string username,pair<EVP_PKEY*,EVP_PKEY*> eph_keys){
    ephemeral_keys[username] = eph_keys;
}

void Session::disconnect_client(int socket) {
    auto usr = users.begin();
    bool done = false;
    while (usr != users.end() && !done) {
        if (socket == usr->second->getSocket()) {
            usr->second->setIsOnline(false);
            string username = usr->second->getUserName();
            //session key
            usr->second->deleteSessionKey();
            //ephemeral keys
            destroy_ephemeral_keys(username);
            usr->second->setSnUser(0);
            usr->second->setSnServer(0);
            done = true;
        }
        usr++;
    }
}

void Session::destroy_ephemeral_keys(std::string username){
    //if there are phemeral keys
    if(ephemeral_keys.find(username) != ephemeral_keys.end()){
        //free ephemeral key
        pair<EVP_PKEY*,EVP_PKEY*> tmp_keys = ephemeral_keys.find(username)->second;
        EVP_PKEY_free(tmp_keys.first);
        EVP_PKEY_free(tmp_keys.second);
        ephemeral_keys.erase(username);
    }
}

pair<EVP_PKEY*,EVP_PKEY*> Session::get_ephemeral_keys(std::string username){
    return ephemeral_keys.at(username);
}

void Session::setServerPvtKey(EVP_PKEY *serverPvtKey) {
    server_pvt_key = serverPvtKey;
}

EVP_PKEY *Session::getServerPvtKey() const {
    return server_pvt_key;
}

X509 *Session::getServerCert() const {
    return server_cert;
}

void Session::setServerCert(X509 *serverCert) {
    server_cert = serverCert;
}

bool Session::is_in_handshake(std::string username) {
    return ephemeral_keys.find(username) != ephemeral_keys.end();
}

std::string Session::get_online_users() {
    string users_online;
    string username;
    auto usr = users.begin();
    while(usr != users.end()){
        if(usr->second->isOnline()) {
            username = usr->second->getUserName();
            users_online.append(username + " ");
        }
        usr++;
    }
    return users_online;
}
