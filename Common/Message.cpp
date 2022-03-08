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
    if(payload)
        delete payload;
}

