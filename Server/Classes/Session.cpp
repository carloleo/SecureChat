//
// Created by crl on 3/1/22.
//

#include "Session.h"

User* Session::get_user(string username) {
    return users.at(username);
}

void Session::add_user(string username) {
    User* usr = new User();
    usr->setUserName(username);
    users[username] = usr;
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
}
