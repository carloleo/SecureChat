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

EVP_PKEY *Payload::getPubKey() const {
    return pub_key;
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

void Payload::setPubKey(EVP_PKEY *tPubKey) {
    pub_key = tPubKey;
}

void Payload::setCert(X509 *cert) {
    Payload::cert = cert;
}

Payload::~Payload() {
    if(signature)
        delete signature;
    if(ciphertext)
        delete ciphertext;
    if(auth_tag)
        delete auth_tag;
    //EVP_PKEY_free(pub_key);

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
    pub_key = nullptr; //ephemeral public key
    cert = nullptr; //certificate
}
