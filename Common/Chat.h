//
// Created by crl on 3/25/22.
//

#ifndef SECURECHAT_CHAT_H
#define SECURECHAT_CHAT_H


#include <string>
/*
 * ADT representing a chat between two users
 */
class Chat {
    std::string requester_peer; // who opened the chat
    std::string target_peer;  // whom to talk
public:
    void setRequesterPeer(const std::string &requesterPeer);

    void setTargetPeer(const std::string &targetPeer);

    const std::string &getTargetPeer() const;

    const std::string &getRequesterPeer() const;
};


#endif //SECURECHAT_CHAT_H
