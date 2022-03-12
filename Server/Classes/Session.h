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
    map<string,User*> users;
    //ephemeral keys for perfect forward secrecy per users
    map<string,pair<EVP_PKEY*,EVP_PKEY*>> ephemeral_keys;
    EVP_PKEY* server_pvt_key;
    X509* server_cert;
public:
    User* get_user(std::string username);
    void add_user(User* user);
    void change_status(std::string username, bool is_online);
    bool is_registered(std::string username);
    void add_ephemeral_keys(string username,pair<EVP_PKEY*,EVP_PKEY*> eph_keys);
    pair<EVP_PKEY*,EVP_PKEY*> get_ephemeral_keys(std::string username);

    X509 *getServerCert() const;

    EVP_PKEY *getServerPvtKey() const;

    void setServerPvtKey(EVP_PKEY *serverPvtKey);

    void setServerCert(X509 *serverCert);

    ~Session();
    //TODO: build the users online list
};


#endif //SECURECHAT_SESSION_H
