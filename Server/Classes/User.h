//
// Created by crl on 3/1/22.
//

#ifndef SECURECHAT_USER_H
#define SECURECHAT_USER_H

#include <string>
#include <openssl/evp.h>

/*
 * ADT representing an user
 */
class User {
private:
    std::string user_name;
    unsigned char *session_key = nullptr;
    bool is_online;
    bool is_busy;
    int socket;
    EVP_PKEY *public_key = nullptr;
    uint32_t sn_user; //sequence numbers
    uint32_t sn_server;
public:
    void setSessionKey(unsigned char *sessionKey);

    void setUserName(const std::string &userName);

    void setIsOnline(bool isOnline);

    void setSocket(int socket);

    void setPublicKey(EVP_PKEY *publicKey);

    void setIsBusy(bool isBusy);

    void setSnUser(uint32_t snUser);

    void setSnServer(uint32_t snServer);

    void deleteSessionKey();

    ~User();

public:
    const std::string &getUserName() const;

    unsigned char *getSessionKey() const;

    bool isOnline() const;

    int getSocket() const;

    EVP_PKEY *getPublicKey() const;

    uint32_t getSnUser() const;

    uint32_t getSnServer() const;

    bool isBusy() const;

    void increment_server_sn();

    void increment_user_sn();
};


#endif //SECURECHAT_USER_H
