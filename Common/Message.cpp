//
// Created by crl on 3/1/22.
//

#include "Message.h"

MESSAGE_TYPE Message::getType() const {
    return type;
}

const std::string &Message::getSender() const {
    return sender;
}

const std::string &Message::getRecipient() const {
    return recipient;
}

Payload *Message::getPayload() const {
    return payload;
}

void Message::setType(MESSAGE_TYPE type) {
    Message::type = type;
}
void Message::setSender(const std::string &sender) {
    Message::sender = sender;
}

void Message::setRecipient(const std::string &recipient) {
    Message::recipient = recipient;
}

void Message::setPayload(Payload *payload) {
    Message::payload = payload;
}

Message::~Message() {
    if(iv)
        delete iv;
    if(payload)
        delete payload;
}

Message::Message() {
    iv = nullptr;
    NEW(payload, new Payload(),"payload")
}

uint32_t Message::getTPkLen() const {
    return t_pk_len;
}

uint32_t Message::getCertLen() const {
    return cert_len;
}

uint32_t Message::getCTxtLen() const {
    return c_txt_len;
}

uint32_t Message::getSequenceN() const {
    return sequence_n;
}

void Message::setTPkLen(uint32_t tPkLen) {
    t_pk_len = tPkLen;
}

void Message::setCertLen(uint32_t certLen) {
    cert_len = certLen;
}

void Message::setCTxtLen(uint32_t cTxtLen) {
    c_txt_len = cTxtLen;
}

void Message::setSequenceN(uint32_t sequenceN) {
    sequence_n = sequenceN;
}

uint32_t Message::getSignatureLen() const {
    return signature_len;
}

void Message::setSignatureLen(uint32_t signatureLen) {
    signature_len = signatureLen;
}

unsigned char *Message::getIv() const {
    return iv;
}

void Message::setIv(unsigned char *iv) {
    Message::iv = iv;
}

