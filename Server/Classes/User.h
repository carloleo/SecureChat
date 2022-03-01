//
// Created by crl on 3/1/22.
//

#ifndef SECURECHAT_USER_H
#define SECURECHAT_USER_H
using namespace std;
#include <string>

class User {
private:
    string user_name;
    unsigned char* session_key;
    bool is_online;
public:
    void setSessionKey(unsigned char *sessionKey);
    void setUserName(const string &userName);
    void setIsOnline(bool isOnline);

public:
    const string &getUserName() const;
    unsigned char *getSessionKey() const;
    bool isOnline() const;
};


#endif //SECURECHAT_USER_H
