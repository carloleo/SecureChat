//
// Created by crl on 3/8/22.
//

#ifndef SECURECHAT_PAYLOAD_H
#define SECURECHAT_PAYLOAD_H
#include <openssl/evp.h>
#include <openssl/pem.h>

class Payload {
    unsigned char* signature;
    unsigned char* ciphertext;
    unsigned char* auth_tag;
    uint32_t nonce;
    EVP_PKEY* t_pub_key; //ephemeral public key
    X509* cert; //certificate
public:
    unsigned char *getSignature() const;

    unsigned char *getCiphertext() const;

    unsigned char *getAuthTag() const;

    uint32_t getNonce() const;

    EVP_PKEY *getTPubKey() const;

    X509 *getCert() const;

    void setSignature(unsigned char *signature);

    void setCiphertext(unsigned char *ciphertext);

    void setAuthTag(unsigned char *authTag);

    void setNonce(uint32_t nonce);

    void setTPubKey(EVP_PKEY *tPubKey);

    void setCert(X509 *cert);

    virtual ~Payload();
};


#endif //SECURECHAT_PAYLOAD_H