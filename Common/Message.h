//
// Created by crl on 3/1/22.
//

#ifndef SECURECHAT_MESSAGE_H
#define SECURECHAT_MESSAGE_H
#include "utility.h"
#include "Payload.h"
#include <string>
#include <cstring>
#include <ostream>

/*
 * ADT representing a message
 */
class Message {
private:
    //header
    MESSAGE_TYPE type;
    ERROR_CODE err_code;
    uint32_t pk_len; //ephemeral public key length
    uint32_t cert_len; // certificate length
    uint32_t c_txt_len; //ciphertext length
    uint32_t sequence_n; //sequence number
    uint32_t peer_sn; //sequence number between peers
    unsigned char* iv; //initialization vector
    unsigned char* peer_iv;//initialization vector between peers
    uint32_t signature_len;
    std::string sender;
    std::string recipient;
    unsigned char* server_auth_tag; // authentication tag between server and client when two users chat
    //payload
    Payload* payload;
public:
    Message();


    Message(MESSAGE_TYPE type);

    MESSAGE_TYPE getType() const;

    const std::string &getSender() const;

    const std::string &getRecipient() const;

    Payload *getPayload() const;

    uint32_t getPkLen() const;

    uint32_t getCertLen() const;

    uint32_t getCTxtLen() const;

    uint32_t getSequenceN() const;

    uint32_t getSignatureLen() const;

    unsigned char *getIv() const;

    ERROR_CODE getErrCode() const;

    unsigned char *getServerAuthTag() const;

    uint32_t getPeerSn() const;

    unsigned char *getPeerIv() const;

    void setType(MESSAGE_TYPE type);

    void setSender(const std::string &sender);

    void setRecipient(const std::string &recipient);

    void setPayload(Payload *payload);

    void setPkLen(uint32_t tPkLen);

    void setCertLen(uint32_t certLen);

    void setCTxtLen(uint32_t cTxtLen);

    void setSequenceN(uint32_t sequenceN);

    void setSignatureLen(uint32_t signatureLen);

    void setIv(unsigned char *iv);

    void setErrCode(ERROR_CODE errCode);

    void setServerAuthTag(unsigned char *serverAuthTag);

    void setPeerSn(uint32_t peerSn);

    void setPeerIv(unsigned char *peerIv);


    virtual ~Message();
};


#endif //SECURECHAT_MESSAGE_H
