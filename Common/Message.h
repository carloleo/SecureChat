//
// Created by crl on 3/1/22.
//

#ifndef SECURECHAT_MESSAGE_H
#define SECURECHAT_MESSAGE_H
#include "utility.h"
#include <string>


class Message {
private:
    //header
    MESSAGE_TYPE type;
    uint32_t  nonce;
    std::string sender;
    std::string recipient;
    //payload
    std::string payload;
public:
    MESSAGE_TYPE getType() const;

    uint32_t getNonce() const;

    const std::string &getSender() const;

    const std::string &getRecipient() const;

    const std::string &getPayload() const;

    void setType(MESSAGE_TYPE type);

    void setNonce(uint32_t nonce);

    void setSender(const std::string &sender);

    void setRecipient(const std::string &recipient);

    void setPayload(const std::string &payload);
};


#endif //SECURECHAT_MESSAGE_H
