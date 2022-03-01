//
// Created by crl on 3/1/22.
//

#include "Message.h"


OP Message::getOp() const {
    return op;
}

uint32_t Message::getNonce() const {
    return nonce;
}

uint32_t Message::getSequenceNumber() const {
    return sequence_number;
}

const string &Message::getUser() const {
    return user;
}

const string &Message::getPayload() const {
    return payload;
}

void Message::setOp(OP op) {
    Message::op = op;
}

void Message::setNonce(uint32_t nonce) {
    Message::nonce = nonce;
}

void Message::setSequenceNumber(uint32_t sequenceNumber) {
    sequence_number = sequenceNumber;
}

void Message::setUser(const string &user) {
    Message::user = user;
}

void Message::setPayload(const string &payload) {
    Message::payload = payload;
}
