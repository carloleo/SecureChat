//
// Created by crl on 3/25/22.
//

#ifndef SECURECHAT_CHAT_H
#define SECURECHAT_CHAT_H


#include <string>

class Chat {
    std::string requester_peer;
    std::string target_peer;
    bool pending;
    bool ongoing;
public:
    void setRequesterPeer(const std::string &requesterPeer);

    void setTargetPeer(const std::string &targetPeer);

    const std::string &getTargetPeer() const;

    const std::string &getRequesterPeer() const;
};


#endif //SECURECHAT_CHAT_H
