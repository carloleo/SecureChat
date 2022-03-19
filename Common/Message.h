//
// Created by crl on 3/1/22.
//

#ifndef SECURECHAT_MESSAGE_H
#define SECURECHAT_MESSAGE_H
#include "utility.h"
#include "Payload.h"
#include <string>
#include <cstring>


class Message {
private:
    //header
    MESSAGE_TYPE type;
    uint32_t t_pk_len; //ephemeral public key length
    uint32_t cert_len; // certificate length
    uint32_t c_txt_len; //ciphertext length
    uint32_t sequence_n; //sequence number
    uint32_t signature_len;
    std::string sender;
    std::string recipient;
    bool result;
    //payload
    Payload* payload;
public:
    Message();


    Message(MESSAGE_TYPE type);

    MESSAGE_TYPE getType() const;

    const std::string &getSender() const;

    const std::string &getRecipient() const;

    Payload *getPayload() const;

    uint32_t getTPkLen() const;

    uint32_t getCertLen() const;

    uint32_t getCTxtLen() const;

    uint32_t getSequenceN() const;

    uint32_t getSignatureLen() const;



    void setType(MESSAGE_TYPE type);

    void setSender(const std::string &sender);

    void setRecipient(const std::string &recipient);

    void setPayload(Payload *payload);

    void setTPkLen(uint32_t tPkLen);

    void setCertLen(uint32_t certLen);

    void setCTxtLen(uint32_t cTxtLen);

    void setSequenceN(uint32_t sequenceN);

    void setSignatureLen(uint32_t signatureLen);


    virtual ~Message();
};


#endif //SECURECHAT_MESSAGE_H
