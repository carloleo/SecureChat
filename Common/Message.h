//
// Created by crl on 3/1/22.
//

#ifndef SECURECHAT_MESSAGE_H
#define SECURECHAT_MESSAGE_H
#include "utility.h"
#include <string>
using namespace std;


class Message {
private:
    //header
    OP op;
    uint32_t  nonce;
    uint32_t sequence_number;
    string user;
    //payload
    string payload;
public:
    void set_op(OP op);
    void set_nonce(uint32_t nonce);
    void set_sequence_number(uint32_t sequence_number);
    void set_user(string user);
    void set_payload(string payload);

    void setOp(OP op);

    void setNonce(uint32_t nonce);

    void setSequenceNumber(uint32_t sequenceNumber);

    void setUser(const string &user);

    void setPayload(const string &payload);

    OP get_op();

    OP getOp() const;

    uint32_t getNonce() const;

    uint32_t getSequenceNumber() const;

    const string &getUser() const;

    const string &getPayload() const;

    uint32_t get_nonce();
    uint32_t get_sequence_number();
    string get_user();
    string get_payload();
};


#endif //SECURECHAT_MESSAGE_H
