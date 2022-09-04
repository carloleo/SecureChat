//
// Created by crl on 3/1/22.
//

#include "Message.h"
/*
 * Message ADT implementation
 * getters and setters
 */

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
    if (iv)
        delete[] iv;
    if (peer_iv)
        delete[] peer_iv;
    if (server_auth_tag)
        delete[] server_auth_tag;
    if (payload)
        delete payload;
}

Message::Message() {
    iv = nullptr;
    peer_iv = nullptr;
    server_auth_tag = nullptr;
    NEW(payload, new Payload(), "payload")
}

uint32_t Message::getPkLen() const {
    return pk_len;
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

void Message::setPkLen(uint32_t tPkLen) {
    pk_len = tPkLen;
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

ERROR_CODE Message::getErrCode() const {
    return err_code;
}

void Message::setErrCode(ERROR_CODE errCode) {
    err_code = errCode;
}

unsigned char *Message::getServerAuthTag() const {
    return server_auth_tag;
}

void Message::setServerAuthTag(unsigned char *serverAuthTag) {
    server_auth_tag = serverAuthTag;
}

uint32_t Message::getPeerSn() const {
    return peer_sn;
}

void Message::setPeerSn(uint32_t peerSn) {
    peer_sn = peerSn;
}

void Message::setPeerIv(unsigned char *peerIv) {
    peer_iv = peerIv;
}

unsigned char *Message::getPeerIv() const {
    return peer_iv;
}

