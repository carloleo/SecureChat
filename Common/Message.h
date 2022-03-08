//
// Created by crl on 3/1/22.
//

#ifndef SECURECHAT_MESSAGE_H
#define SECURECHAT_MESSAGE_H
#include "utility.h"
#include "Payload.h"
#include <string>


class Message {
private:
    //header
    MESSAGE_TYPE type;
    uint32_t t_pk_len; //ephemeral public key length
    uint32_t cert_len; // certificate length
    uint32_t c_txt_len; //ciphertext length
    uint32_t sequence_n; //sequence number
    std::string sender;
    std::string recipient;
    //payload
    Payload* payload;
public:
    MESSAGE_TYPE getType() const;

    const std::string &getSender() const;

    const std::string &getRecipient() const;

    Payload *getPayload() const;

    void setType(MESSAGE_TYPE type);

    void setSender(const std::string &sender);

    void setRecipient(const std::string &recipient);

    void setPayload(Payload *payload);

    virtual ~Message();
};


#endif //SECURECHAT_MESSAGE_H
