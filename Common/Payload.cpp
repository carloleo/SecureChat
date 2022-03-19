//
// Created by crl on 3/8/22.
//

#include "Payload.h"

unsigned char *Payload::getSignature() const {
    return signature;
}

unsigned char *Payload::getCiphertext() const {
    return ciphertext;
}

unsigned char *Payload::getAuthTag() const {
    return auth_tag;
}

uint32_t Payload::getNonce() const {
    return nonce;
}

EVP_PKEY *Payload::getTPubKey() const {
    return t_pub_key;
}

X509 *Payload::getCert() const {
    return cert;
}

void Payload::setSignature(unsigned char *signature) {
    Payload::signature = signature;
}

void Payload::setCiphertext(unsigned char *ciphertext) {
    Payload::ciphertext = ciphertext;
}

void Payload::setAuthTag(unsigned char *authTag) {
    auth_tag = authTag;
}

void Payload::setNonce(uint32_t nonce) {
    Payload::nonce = nonce;
}

void Payload::setTPubKey(EVP_PKEY *tPubKey) {
    t_pub_key = tPubKey;
}

void Payload::setCert(X509 *cert) {
    Payload::cert = cert;
}

Payload::~Payload() {
    if(signature)
        free(signature);
    if(ciphertext)
        free(ciphertext);
    if(auth_tag)
        free(auth_tag);
    EVP_PKEY_free(t_pub_key);

}

const std::string &Payload::getErrorMessage() const {
    return error_message;
}

void Payload::setErrorMessage(const std::string &errorMessage) {
    error_message = errorMessage;
}

Payload::Payload() {
    signature = nullptr;
    ciphertext = nullptr;
    auth_tag = nullptr;
    t_pub_key = nullptr; //ephemeral public key
    cert = nullptr; //certificate
}
