//
// Created by crl on 3/8/22.
//

#ifndef SECURECHAT_PAYLOAD_H
#define SECURECHAT_PAYLOAD_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <iostream>

/*
 * ADT representing message's payload
 */
class Payload {
    unsigned char *signature;
    unsigned char *ciphertext;
    unsigned char *auth_tag;
    std::string error_message;
    uint32_t nonce;
    EVP_PKEY *pub_key; //ephemeral public key or peer's public key
    X509 *cert; //certificate
public:
    Payload();

    unsigned char *getSignature() const;

    unsigned char *getCiphertext() const;

    unsigned char *getAuthTag() const;

    uint32_t getNonce() const;

    EVP_PKEY *getPubKey() const;

    X509 *getCert() const;

    const std::string &getErrorMessage() const;

    void setSignature(unsigned char *signature);

    void setCiphertext(unsigned char *ciphertext);

    void setAuthTag(unsigned char *authTag);

    void setNonce(uint32_t nonce);

    void setPubKey(EVP_PKEY *tPubKey);

    void setCert(X509 *cert);

    void setErrorMessage(const std::string &errorMessage);

    virtual ~Payload();
};


#endif //SECURECHAT_PAYLOAD_H
