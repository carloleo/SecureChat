//
// Created by crl on 3/1/22.
//

#include "Message.h"

MESSAGE_TYPE Message::getType() const {
    return type;
}

uint32_t Message::getNonce() const {
    return nonce;
}

const string &Message::getSender() const {
    return sender;
}

const string &Message::getRecipient() const {
    return recipient;
}

const string &Message::getPayload() const {
    return payload;
}

void Message::setType(MESSAGE_TYPE type) {
    Message::type = type;
}

void Message::setNonce(uint32_t nonce) {
    Message::nonce = nonce;
}

void Message::setSender(const string &sender) {
    Message::sender = sender;
}

void Message::setRecipient(const string &recipient) {
    Message::recipient = recipient;
}

void Message::setPayload(const string &payload) {
    Message::payload = payload;
}
