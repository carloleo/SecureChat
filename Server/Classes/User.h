//
// Created by crl on 3/1/22.
//

#ifndef SECURECHAT_USER_H
#define SECURECHAT_USER_H

#include <string>

class User {
private:
    std::string user_name;
    unsigned char* session_key;
    bool is_online;
public:
    void setSessionKey(unsigned char *sessionKey);
    void setUserName(const std::string &userName);
    void setIsOnline(bool isOnline);
    void deleteSessionKey() const;
    ~User();

public:
    const std::string &getUserName() const;
    unsigned char *getSessionKey() const;
    bool isOnline() const;
};


#endif //SECURECHAT_USER_H
