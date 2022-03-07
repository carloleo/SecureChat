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

const std::string &Message::getSender() const {
    return sender;
}

const std::string &Message::getRecipient() const {
    return recipient;
}

const std::string &Message::getPayload() const {
    return payload;
}

void Message::setType(MESSAGE_TYPE type) {
    Message::type = type;
}

void Message::setNonce(uint32_t nonce) {
    Message::nonce = nonce;
}

void Message::setSender(const std::string &sender) {
    Message::sender = sender;
}

void Message::setRecipient(const std::string &recipient) {
    Message::recipient = recipient;
}

void Message::setPayload(const std::string &payload) {
    Message::payload = payload;
}
