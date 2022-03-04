//
// Created by crl on 3/1/22.
//

#ifndef SECURECHAT_MESSAGE_H
#define SECURECHAT_MESSAGE_H
#include "utility.h"
#include <string>
using namespace std;


class Message {
private:
    //header
    MESSAGE_TYPE type;
    uint32_t  nonce;
    string sender;
    string recipient;
    //payload
    string payload;
public:
    MESSAGE_TYPE getType() const;

    uint32_t getNonce() const;

    const string &getSender() const;

    const string &getRecipient() const;

    const string &getPayload() const;

    void setType(MESSAGE_TYPE type);

    void setNonce(uint32_t nonce);

    void setSender(const string &sender);

    void setRecipient(const string &recipient);

    void setPayload(const string &payload);
};


#endif //SECURECHAT_MESSAGE_H
