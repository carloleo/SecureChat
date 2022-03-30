//
// Created by crl on 3/1/22.
//

#include "Session.h"
#include "../../Common/Message.h"
#include "../Managers/managers.h"
using namespace Managers;
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
    User* notified_user = nullptr;
    Message message;
    string notified_username;
    unsigned char* iv = nullptr;
    int result = 0;
    int socket_to_disconnect = -1;
    auto usr = users.begin();
    bool done = false;
    while (usr != users.end() && !done) {
        if (socket == usr->second->getSocket() && usr->second->isOnline()) {
            usr->second->setIsOnline(false);
            string username = usr->second->getUserName();
            //session key
            usr->second->deleteSessionKey();
            //ephemeral keys
            destroy_ephemeral_keys(username);
            usr->second->setSnUser(0);
            usr->second->setSnServer(0);
            usr->second->setIsBusy(false);
            auto chat = chats.begin();
            bool found = false;
            while(!found && chat != chats.end()){

                //target user disconnected
                if((*chat)->getTargetPeer().compare(usr->second->getUserName()) == 0)
                    notified_user = users.at((*chat)->getRequesterPeer()); //notify requester
                //requester user disconnected
                else if((*chat)->getRequesterPeer().compare(usr->second->getUserName()) == 0)
                    notified_user = users.at((*chat)->getTargetPeer()); //notify target user
                //if disconnect user is in a chat
                if(notified_user != nullptr){
                    notified_user->setIsBusy(false);
                    message.setType(ERROR);
                    message.setErrCode(PEER_DISCONNECTED);
                    message.setSequenceN(notified_user->getSnServer());
                    iv = CryptoManager::generate_iv();
                    message.setIv(iv);
                    //notify the mate
                    result = Managers::SocketManager::send_authenticated_message(notified_user->getSocket(),
                                                                        &message,notified_user->getSessionKey());
                    if(result)
                        notified_user->increment_server_sn();
                    else
                        socket_to_disconnect = notified_user->getSocket();
                    chat = chats.erase(chat);
                    found = true;

                }
                else chat++;
            }
            done = true;
        }
        usr++;
    }
//    if(socket_to_disconnect != -1)
//        disconnect_client(socket_to_disconnect);
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

void Session::open_chat(std::string requester, std::string target) {
    Chat* chat;
    try{
        chat = new Chat();
    }
    catch (bad_alloc &e){
        exit(EXIT_FAILURE);
    }
    chat->setRequesterPeer(requester);
    chat->setTargetPeer(target);
    chats.push_back(chat);
}

void Session::close_chat(std::string requester, std::string target) {
    auto it = chats.begin();
    bool done = false;
    while (!done && it != chats.end()){
        if((*it)->getRequesterPeer().compare(requester) == 0
           && (*it)->getTargetPeer().compare(target) == 0){
            it = chats.erase(it);
            done = true;
        }
        it++;
    }
}

Chat* Session::get_chat_by_usr(std::string user) {
    auto it = chats.begin();
    bool found = false;
    while (!found && it != chats.end()) {
        if ((*it)->getRequesterPeer().compare(user) == 0
            or (*it)->getTargetPeer().compare(user) == 0) {
            found = true;
        } else it++;
    }
    return  found ? *it : nullptr;
}
