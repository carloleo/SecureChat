//
// Created by crl on 3/1/22.
//

#ifndef SECURECHAT_SESSION_H
#define SECURECHAT_SESSION_H
#include <map>
#include <string>
#include "User.h"
using namespace std;
class Session {
private:
    map<string,User> users;
public:
    User get_user(string username);
    void add_user(string username,User user);
    void change_status(string username, bool is_online);
    //TODO: build the users online list
};


#endif //SECURECHAT_SESSION_H
