//
// Created by crl on 3/25/22.
//

#include "Chat.h"

/*
 * Chat ADT implementation
 */
void Chat::setRequesterPeer(const std::string &requesterPeer) {
    requester_peer = requesterPeer;
}

void Chat::setTargetPeer(const std::string &targetPeer) {
    target_peer = targetPeer;
}

const std::string &Chat::getRequesterPeer() const {
    return requester_peer;
}

const std::string &Chat::getTargetPeer() const {
    return target_peer;
}
