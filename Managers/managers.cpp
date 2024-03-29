//
// Created by crl on 2/24/22.
//

#include "managers.h"
#include <csignal>
#include <cerrno>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <iostream>
#include <string>
#include <limits>
#include <cstring>
// Library MACRO

#define OPENSSL_FAIL(result, message, error_value) \
       if(!result) {              \
            Managers::CryptoManager::manage_error(message);                         \
            return error_value;                                  \
       }
#define IF_IO_ERROR(result, error_value) \
        if(result <= 0){                 \
            if(errno != 0)              \
                perror("I/O ERROR");                         \
            return error_value; \
        }
#define BIO_FAIL(result, message, error_value) \
        if(result <= 0){                               \
             Managers::CryptoManager::manage_error(message);       \
                    return error_value;  \
        }

using namespace std;
/*
 * LIBRARY IMPLEMENTATION
 */
int Managers::SocketManager::write_n(int socket, size_t amount, void *buff) {
    size_t left = amount;
    size_t n;
    char *buff_ptr = (char *) buff;
    while (left > 0) {
        n = write(socket, buff_ptr, amount);
        if (n == -1) {
            if (errno == EINTR) continue;
            else if (errno == EPIPE) return 0; //ignore
            return -1;
        }
        if (n == 0) return 0;
        left -= n;
        buff_ptr += n;

    }
    return 1;
}

int Managers::SocketManager::read_n(int socket, size_t amount, void *buff) {
    size_t left = amount;
    size_t n;
    char *buff_ptr = (char *) buff;
    while (left > 0) {
        n = read(socket, buff_ptr, amount);
        if (n == -1) {
            if (errno == EINTR) continue;
            else if (errno == ECONNRESET) return 0; //ignore
            return -1;
        }
        if (n == 0) return 0;
        left -= n;
        buff_ptr += n;
    }
    return 1;
}

int Managers::SocketManager::write_string(int socket, std::string str) {
    size_t size = str.length();
    int result;
    result = SocketManager::write_n(socket, sizeof(size_t), (void *) &size);
    if (result <= 0)
        return result;
    result = SocketManager::write_n(socket, size, (void *) str.c_str());
    return result;
}

int Managers::SocketManager::send_certificate(int socket, X509 *cert) {
    int result;
    char *cert_buff = NULL;
    long size;
    BIO *stream = BIO_new(BIO_s_mem());
    OPENSSL_FAIL(stream, "allocating bio stream failed", 0)
    result = PEM_write_bio_X509(stream, cert);
    OPENSSL_FAIL(result, "writing cert on bio stream failed", 0)
    size = BIO_get_mem_data(stream, &cert_buff);
    OPENSSL_FAIL(size, "getting cert from bio stream failed", 0)
    //send certificate size
    result = SocketManager::write_n(socket, sizeof(long), (void *) &size);
    IF_IO_ERROR(result, result);
    //send certificate
    result = SocketManager::write_n(socket, size, (void *) cert_buff);
    BIO_free(stream);
    return result;
}

int Managers::SocketManager::send_public_key(int socket, EVP_PKEY *pubkey) {
    int result;
    char *pub_key_buff = NULL;
    long size;
    BIO *stream = BIO_new(BIO_s_mem());
    OPENSSL_FAIL(stream, "allocating bio stream failed", 0)
    result = PEM_write_bio_PUBKEY(stream, pubkey);
    OPENSSL_FAIL(result, "writing pubkey on bio stream failed", 0)
    size = BIO_get_mem_data(stream, &pub_key_buff);
    OPENSSL_FAIL(size, "getting pubkey from bio stream failed", 0)
    //send public key size
    result = SocketManager::write_n(socket, sizeof(long), (void *) &size);
    IF_IO_ERROR(result, result);
    //send pub key
    result = SocketManager::write_n(socket, size, (void *) pub_key_buff);
    BIO_free(stream);
    return result;
}

int Managers::SocketManager::send_data(int socket, unsigned char *data, uint32_t len) {
    int result;
    //send size
    result = SocketManager::write_n(socket, sizeof(uint32_t), (void *) &len);
    IF_IO_ERROR(result, 0)
    //send data
    result = SocketManager::write_n(socket, len,
                                    (void *) data);
    return result;
}

int Managers::SocketManager::read_data(int socket, unsigned char **data, uint32_t *len) {
    int result;
    //read size
    result = SocketManager::read_n(socket, sizeof(uint32_t), (void *) len);
    IF_IO_ERROR(result, 0)
    NEW(*data, new unsigned char[*len], "data")
    //read data
    result = SocketManager::read_n(socket, *len,
                                   (void *) *data);
    return result;
}

int Managers::SocketManager::read_certificate(int socket, X509 **cert) {
    int result;
    unsigned char *cert_buff = NULL;
    long size;
    BIO *stream;
    result = SocketManager::read_n(socket, sizeof(long), (void *) &size);
    IF_IO_ERROR(result, result);
    NEW(cert_buff, new unsigned char[size], "cert_buff")
    result = SocketManager::read_n(socket, size, (void *) cert_buff);
    IF_IO_ERROR(result, result);
    stream = BIO_new(BIO_s_mem());
    OPENSSL_FAIL(stream, "allocating bio stream failed", 0)
    result = BIO_write(stream, cert_buff, size);
    OPENSSL_FAIL(stream, "writing certificate to bio stream failed", 0)
    *cert = PEM_read_bio_X509(stream, NULL, NULL, NULL);
    BIO_free(stream);
    delete[] cert_buff;
    return *cert != NULL ? 1 : 0;


}

int Managers::SocketManager::send_encrypted_message(int socket, uint32_t sequence_number, unsigned char *session_key,
                                                    string body, MESSAGE_TYPE type) {
    unsigned char *auth_tag;
    unsigned char *ciphertext;
    uint32_t cipher_len;
    int result = 0;
    unsigned char *aad;
    unsigned char *iv;
    size_t aad_len;
    int to_allocate = -1;
    iv = CryptoManager::generate_iv();
    IF_MANAGER_FAILED(iv, "send_encrypted_message generating iv failed", 0)
    size_t plain_size;
    plain_size = body.length();
    to_allocate = plain_size + BLOCK_SIZE;
    NEW(auth_tag, new unsigned char[TAG_LEN], "auth_tag")
    NEW(ciphertext, new unsigned char[to_allocate], "ciphertext")
    //prepare message
    Message *message = new Message();
    message->setType(type);
    message->setSequenceN(sequence_number);
    message->setIv(iv);
    //get additional authentication data
    aad_len = CryptoManager::message_to_bytes(message, &aad);
    cipher_len = CryptoManager::gcm_encrypt((unsigned char *) body.c_str(), plain_size,
                                            aad, aad_len, session_key,
                                            iv, IV_LEN, ciphertext, auth_tag);
    IF_MANAGER_FAILED(cipher_len, "encrypting last handshake message failed", 0)
    //add encryption fields
    message->setCTxtLen(cipher_len);
    message->getPayload()->setCiphertext(ciphertext);
    message->getPayload()->setAuthTag(auth_tag);
    //send message
    result = SocketManager::send_message(socket, message);
    delete message;
    delete[] aad;
    IF_MANAGER_FAILED(result, "sending last handshake message failed", 0)
    return result;
}

int Managers::SocketManager::send_authenticated_message(int socket, Message *message, unsigned char *key,
                                                        bool for_peer) {
    unsigned char *aad = nullptr;
    unsigned char *tag = nullptr;
    size_t aad_size;
    int not_used = 0;
    //iv set into message
    aad_size = Managers::CryptoManager::message_to_bytes(message, &aad);
    IF_MANAGER_FAILED(aad_size, "send_authenticated_message getting aad failed", 0)
    NEW(tag, new unsigned char[TAG_LEN], "send_authenticated_message allocating tag")
    not_used = CryptoManager::authenticate_data(aad, aad_size, message->getIv(), key, tag);
    delete[] aad;
    IF_MANAGER_FAILED(not_used, "send_authenticated_message failed", 0)
    if (for_peer)
        message->setServerAuthTag(tag);
    else
        message->getPayload()->setAuthTag(tag);
    not_used = SocketManager::send_message(socket, message);
    IF_MANAGER_FAILED(not_used, "send_authenticated_message sending message failed", 0)
    return 1;

}

int Managers::SocketManager::read_public_key(int socket, EVP_PKEY **pubkey) {
    int result;
    unsigned char *pub_key_buff = NULL;
    long size;
    BIO *stream;
    result = SocketManager::read_n(socket, sizeof(long), (void *) &size);
    IF_IO_ERROR(result, result);
    NEW(pub_key_buff, new unsigned char[size], "pub_key_buff")
    result = SocketManager::read_n(socket, size, (void *) pub_key_buff);
    IF_IO_ERROR(result, result);
    stream = BIO_new(BIO_s_mem());
    OPENSSL_FAIL(stream, "allocating bio stream failed", 0)
    result = BIO_write(stream, pub_key_buff, size);
    OPENSSL_FAIL(stream, "writing pub key to bio stream failed", 0)
    *pubkey = PEM_read_bio_PUBKEY(stream, NULL, NULL, NULL);
    BIO_free(stream);
    delete[] pub_key_buff;
    return *pubkey != NULL ? 1 : 0;

}

int Managers::SocketManager::read_string(int socket, std::string &str) {
    size_t size;
    int result;
    result = SocketManager::read_n(socket, sizeof(size_t), (void *) &size);
    if (result <= 0)
        return result;
    char *data;
    NEW(data, new char[size + 1], "data string")
    result = SocketManager::read_n(socket, size, (void *) data);
    if (result) {
        data[size] = '\0';
        str.append(data);
    }
    delete[] data;
    return result;

}

int Managers::SocketManager::send_message(int socket, Message *msg) {
    int result;
    uint32_t nonce;
    int tmp;
    uint32_t len;
    uint32_t sequence_number;
    unsigned char *iv;
    int error_code;
    //send type
    tmp = msg->getType();
    result = SocketManager::write_n(socket, sizeof(int), (void *) &tmp);
    IF_IO_ERROR(result, 0)
    switch (msg->getType()) {
        case AUTH_REQUEST:
            result = SocketManager::write_string(socket, msg->getSender());
            IF_IO_ERROR(result, 0)
            nonce = msg->getPayload()->getNonce();
            result = SocketManager::write_n(socket, sizeof(uint32_t), (void *) &nonce);
            break;
        case AUTH_RESPONSE:
            len = msg->getSignatureLen();
            result = SocketManager::send_data(socket, msg->getPayload()->getSignature(), len);
            IF_IO_ERROR(result, 0)
            //send ephemeral public key
            result = SocketManager::send_public_key(socket, msg->getPayload()->getPubKey());
            IF_IO_ERROR(result, 0)
            result = SocketManager::send_certificate(socket, msg->getPayload()->getCert());
            break;
        case AUTH_KEY_EXCHANGE:
            //send sender's username
            result = SocketManager::write_string(socket, msg->getSender());
            IF_IO_ERROR(result, 0);
            //send signature
            len = msg->getSignatureLen();
            result = SocketManager::send_data(socket, msg->getPayload()->getSignature(), len);
            IF_IO_ERROR(result, 0)
            //send encrypted session key
            len = msg->getCTxtLen();
            result = SocketManager::send_data(socket, msg->getPayload()->getCiphertext(), len);
            IF_IO_ERROR(result, result);
            break;
        case AUTH_KEY_EXCHANGE_RESPONSE:
            //send sequence number
            sequence_number = msg->getSequenceN();
            result = SocketManager::write_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, 0)
            //send iv
            iv = msg->getIv();
            result = SocketManager::send_data(socket, iv, IV_LEN);
            IF_IO_ERROR(result, 0);
            //send encrypted online users list
            len = msg->getCTxtLen();
            result = SocketManager::send_data(socket, msg->getPayload()->getCiphertext(), len);
            IF_IO_ERROR(result, 0);
            //send authentication tag
            result = SocketManager::send_data(socket, msg->getPayload()->getAuthTag(), TAG_LEN);
            IF_IO_ERROR(result, 0);
            break;
        case REQUEST_TO_TALK:
        case REQUEST_OK:
        case REQUEST_KO:
            sequence_number = msg->getSequenceN();
            //send sequence number
            result = SocketManager::write_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, 0)
            iv = msg->getIv();
            //send iv
            result = SocketManager::send_data(socket, iv, IV_LEN);
            IF_IO_ERROR(result, 0);
            //send tag
            result = SocketManager::send_data(socket, msg->getPayload()->getAuthTag(), TAG_LEN);
            IF_IO_ERROR(result, 0)
            //send sender
            result = SocketManager::write_string(socket, msg->getSender());
            IF_IO_ERROR(result, 0)
            //send recipient
            result = SocketManager::write_string(socket, msg->getRecipient());
            IF_IO_ERROR(result, 0)
            break;
        case USERS_LIST:
            sequence_number = msg->getSequenceN();
            result = SocketManager::write_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, 0)
            iv = msg->getIv();
            result = SocketManager::send_data(socket, iv, IV_LEN);
            IF_IO_ERROR(result, 0);
            result = SocketManager::write_string(socket, msg->getSender());
            IF_IO_ERROR(result, 0)
            result = SocketManager::send_data(socket, msg->getPayload()->getAuthTag(), TAG_LEN);
            IF_IO_ERROR(result, 0)
            break;
        case USERS_LIST_RESPONSE:
            sequence_number = msg->getSequenceN();
            result = SocketManager::write_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, 0)
            iv = msg->getIv();
            result = SocketManager::send_data(socket, iv, IV_LEN);
            IF_IO_ERROR(result, 0);
            result = SocketManager::send_data(socket, msg->getPayload()->getAuthTag(), TAG_LEN);
            IF_IO_ERROR(result, 0)
            result = SocketManager::send_data(socket, msg->getPayload()->getCiphertext(), msg->getCTxtLen());
            IF_IO_ERROR(result, 0)
            break;
        case PEER_PUB_KEY:
            sequence_number = msg->getSequenceN();
            result = SocketManager::write_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, 0)
            iv = msg->getIv();
            result = SocketManager::send_data(socket, iv, IV_LEN);
            IF_IO_ERROR(result, 0);
            result = SocketManager::send_data(socket, msg->getPayload()->getAuthTag(), TAG_LEN);
            IF_IO_ERROR(result, 0)
            result = SocketManager::write_string(socket, msg->getSender());
            IF_IO_ERROR(result, 0)
            result = SocketManager::send_public_key(socket, msg->getPayload()->getPubKey());
            IF_IO_ERROR(result, 0)
            break;
        case AUTH_PEER_REQUEST:
            sequence_number = msg->getSequenceN();
            result = SocketManager::write_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, 0)
            iv = msg->getIv();
            result = SocketManager::send_data(socket, iv, IV_LEN);
            IF_IO_ERROR(result, 0);
            result = SocketManager::send_data(socket, msg->getPayload()->getAuthTag(), TAG_LEN);
            IF_IO_ERROR(result, 0)
            nonce = msg->getPayload()->getNonce();
            result = SocketManager::write_n(socket, sizeof(uint32_t), (void *) &nonce);
            IF_IO_ERROR(result, 0)
            result = SocketManager::write_string(socket, msg->getSender());
            IF_IO_ERROR(result, 0)
            result = SocketManager::write_string(socket, msg->getRecipient());
            IF_IO_ERROR(result, 0)
            break;
        case AUTH_PEER_RESPONSE:
            sequence_number = msg->getSequenceN();
            //send sequence number
            result = SocketManager::write_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, 0)
            iv = msg->getIv();
            //send iv
            result = SocketManager::send_data(socket, iv, IV_LEN);
            IF_IO_ERROR(result, 0);
            //send auth tag
            result = SocketManager::send_data(socket, msg->getPayload()->getAuthTag(), TAG_LEN);
            IF_IO_ERROR(result, 0)
            //send public key
            result = SocketManager::send_public_key(socket, msg->getPayload()->getPubKey());
            IF_IO_ERROR(result, 0)
            //send signature
            len = msg->getSignatureLen();
            result = SocketManager::send_data(socket, msg->getPayload()->getSignature(), len);
            IF_IO_ERROR(result, 0);
            //send sender
            result = SocketManager::write_string(socket, msg->getSender());
            IF_IO_ERROR(result, 0)
            //send receiver
            result = SocketManager::write_string(socket, msg->getRecipient());
            IF_IO_ERROR(result, 0)
            break;
        case AUTH_PEER_KEY_EX:
            sequence_number = msg->getSequenceN();
            //send sequence number
            result = SocketManager::write_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, 0)
            //send iv
            iv = msg->getIv();
            result = SocketManager::send_data(socket, iv, IV_LEN);
            IF_IO_ERROR(result, 0);
            //send auth tag
            result = SocketManager::send_data(socket, msg->getPayload()->getAuthTag(), TAG_LEN);
            IF_IO_ERROR(result, 0)
            //send signature
            len = msg->getSignatureLen();
            result = SocketManager::send_data(socket, msg->getPayload()->getSignature(), len);
            IF_IO_ERROR(result, 0)
            //send encrypted session key
            len = msg->getCTxtLen();
            result = SocketManager::send_data(socket, msg->getPayload()->getCiphertext(), len);
            IF_IO_ERROR(result, 0);
            //send sender  username
            result = SocketManager::write_string(socket, msg->getSender());
            IF_IO_ERROR(result, 0);
            //send recipient username
            result = SocketManager::write_string(socket, msg->getRecipient());
            IF_IO_ERROR(result, 0);
            break;
        case AUTH_PEER_KEY_EX_RX:
        case DATA:
            sequence_number = msg->getSequenceN();
            //send sever sequence number
            result = SocketManager::write_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, 0)
            sequence_number = msg->getPeerSn();
            //send peer sequence number
            result = SocketManager::write_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, 0)
            //send server iv
            iv = msg->getIv();
            result = SocketManager::send_data(socket, iv, IV_LEN);
            IF_IO_ERROR(result, 0);
            iv = msg->getPeerIv();
            //send peer iv
            result = SocketManager::send_data(socket, iv, IV_LEN);
            IF_IO_ERROR(result, 0);
            //send server tag
            result = SocketManager::send_data(socket, msg->getServerAuthTag(), TAG_LEN);
            IF_IO_ERROR(result, 0)
            //send peer tag
            result = SocketManager::send_data(socket, msg->getPayload()->getAuthTag(), TAG_LEN);
            IF_IO_ERROR(result, 0)
            //send ciphertext
            len = msg->getCTxtLen();
            result = SocketManager::send_data(socket, msg->getPayload()->getCiphertext(), len);
            IF_IO_ERROR(result, 0);
            //send sender  username
            result = SocketManager::write_string(socket, msg->getSender());
            IF_IO_ERROR(result, 0);
            //send recipient username
            result = SocketManager::write_string(socket, msg->getRecipient());
            IF_IO_ERROR(result, 0);
            break;
        case PEER_QUIT:
            //send sequence number
            sequence_number = msg->getSequenceN();
            result = SocketManager::write_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, 0)
            //send iv
            iv = msg->getIv();
            result = SocketManager::send_data(socket, iv, IV_LEN);
            IF_IO_ERROR(result, 0);
            //send auth tag
            result = SocketManager::send_data(socket, msg->getPayload()->getAuthTag(), TAG_LEN);
            IF_IO_ERROR(result, 0)
            //send sender  username
            result = SocketManager::write_string(socket, msg->getSender());
            IF_IO_ERROR(result, 0);
            break;
        case ERROR:
            sequence_number = msg->getSequenceN();
            result = SocketManager::write_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, 0)
            error_code = msg->getErrCode();
            result = SocketManager::write_n(socket, sizeof(int), (void *) &error_code);
            IF_IO_ERROR(result, 0)
            iv = msg->getIv();
            result = SocketManager::send_data(socket, iv, IV_LEN);
            IF_IO_ERROR(result, 0);
            result = SocketManager::send_data(socket, msg->getPayload()->getAuthTag(), TAG_LEN);
            IF_IO_ERROR(result, 0)
            break;
        case CLIENT_DONE:
            sequence_number = msg->getSequenceN();
            result = SocketManager::write_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, 0)
            //send iv
            iv = msg->getIv();
            result = SocketManager::send_data(socket, iv, IV_LEN);
            IF_IO_ERROR(result, 0);
            //send auth tag
            result = SocketManager::send_data(socket, msg->getPayload()->getAuthTag(), TAG_LEN);
            IF_IO_ERROR(result, 0)
            //send sender  username
            result = SocketManager::write_string(socket, msg->getSender());
            IF_IO_ERROR(result, 0);
            break;
        default:
            break;
    }
    return result;
}

Message *Managers::SocketManager::read_message(int socket) {
    int result;
    Message *msg = nullptr;
    int tmp;
    int error_code;
    uint32_t nonce;
    uint32_t sequence_number;
    uint32_t peer_sn;
    EVP_PKEY *pub_key = nullptr;
    X509 *cert = nullptr;
    unsigned char *signature;
    uint32_t signature_len;
    unsigned char *ciphertext;
    uint32_t ciphertext_len;
    unsigned char *iv;
    unsigned char *peer_iv;
    unsigned char *auth_tag;
    unsigned char *peer_auth_tag;
    string username;
    string sender;
    string recipient;
    string error_message;
    //OPENSSL_FAIL(m_bio,"allocating bio fail",0)
    int type = 0;
    uint32_t size;
    result = SocketManager::read_n(socket, sizeof(int), (void *) &type);
    IF_IO_ERROR(result, nullptr)
    switch (type) {
        case AUTH_REQUEST:
            //read username
            result = SocketManager::read_string(socket, username);
            IF_IO_ERROR(result, nullptr)
            result = SocketManager::read_n(socket, sizeof(uint32_t), (void *) &nonce);
            IF_IO_ERROR(result, nullptr)
            NEW(msg, new Message(), "msg read_message")
            msg->setType(AUTH_REQUEST);
            msg->setSender(username);
            msg->getPayload()->setNonce(nonce);
            break;
        case AUTH_RESPONSE:
            //read signature
            result = SocketManager::read_data(socket, &signature, &signature_len);
            IF_IO_ERROR(result, nullptr)
            //read ephemeral public key
            result = SocketManager::read_public_key(socket, &pub_key);
            IF_IO_ERROR(result, nullptr)
            //read certificate
            result = SocketManager::read_certificate(socket, &cert);
            IF_IO_ERROR(result, nullptr)
            NEW(msg, new Message(), "msg read_message")
            msg->setType(AUTH_RESPONSE);
            msg->setSignatureLen(signature_len);
            msg->getPayload()->setSignature(signature);
            msg->getPayload()->setPubKey(pub_key);
            msg->getPayload()->setCert(cert);
            break;
        case AUTH_KEY_EXCHANGE:
            //read sender's username
            result = SocketManager::read_string(socket, username);
            IF_IO_ERROR(result, nullptr);
            //read signature
            result = SocketManager::read_data(socket, &signature, &signature_len);
            IF_IO_ERROR(result, nullptr)
            //read encrypted session key
            result = SocketManager::read_data(socket, &ciphertext, &ciphertext_len);
            IF_IO_ERROR(result, nullptr);
            NEW(msg, new Message(), "msg read_message")
            msg->setType(AUTH_KEY_EXCHANGE);
            msg->setSender(username);
            msg->setSignatureLen(signature_len);
            msg->getPayload()->setSignature(signature);
            msg->setCTxtLen(ciphertext_len);
            msg->getPayload()->setCiphertext(ciphertext);
            break;
        case AUTH_KEY_EXCHANGE_RESPONSE:
            result = SocketManager::read_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, nullptr)
            //read iv
            result = SocketManager::read_data(socket, &iv, &size);
            IF_IO_ERROR(result, nullptr);
            //read encrypted online users list
            result = SocketManager::read_data(socket, &ciphertext, &ciphertext_len);
            IF_IO_ERROR(result, nullptr);
            //read authentication tag
            result = SocketManager::read_data(socket, &auth_tag, &size);
            IF_IO_ERROR(result, nullptr);
            NEW(msg, new Message(), "msg read_message")
            msg->setType(AUTH_KEY_EXCHANGE_RESPONSE);
            msg->setSequenceN(sequence_number);
            msg->setIv(iv);
            msg->setCTxtLen(ciphertext_len);
            msg->getPayload()->setCiphertext(ciphertext);
            msg->getPayload()->setAuthTag(auth_tag);
            break;
        case REQUEST_TO_TALK:
        case REQUEST_OK:
        case REQUEST_KO:
            result = SocketManager::read_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, nullptr)
            result = SocketManager::read_data(socket, &iv, &size);
            IF_IO_ERROR(result, nullptr)
            result = SocketManager::read_data(socket, &auth_tag, &size);
            IF_IO_ERROR(result, nullptr)
            result = SocketManager::read_string(socket, sender);
            IF_IO_ERROR(result, nullptr)
            result = SocketManager::read_string(socket, recipient);
            IF_IO_ERROR(result, nullptr)
            NEW(msg, new Message(), "read_message allocating message failed");
            msg->setType(type == REQUEST_TO_TALK ? REQUEST_TO_TALK :
                         type == REQUEST_OK ? REQUEST_OK : REQUEST_KO);
            msg->setSender(sender);
            msg->setRecipient(recipient);
            msg->setIv(iv);
            msg->setSequenceN(sequence_number);
            msg->getPayload()->setAuthTag(auth_tag);
            break;
        case USERS_LIST:
            result = SocketManager::read_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, nullptr)
            result = SocketManager::read_data(socket, &iv, &size);
            IF_IO_ERROR(result, nullptr)
            result = SocketManager::read_string(socket, sender);
            IF_IO_ERROR(result, nullptr)
            result = SocketManager::read_data(socket, &auth_tag, &size);
            IF_IO_ERROR(result, nullptr)
            NEW(msg, new Message(), "read_message allocating message failed")
            msg->setType(USERS_LIST);
            msg->setSender(sender);
            msg->setSequenceN(sequence_number);
            msg->setIv(iv);
            msg->getPayload()->setAuthTag(auth_tag);
            break;
        case USERS_LIST_RESPONSE:
            //read sn
            result = SocketManager::read_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, nullptr)
            //read iv
            result = SocketManager::read_data(socket, &iv, &size);
            IF_IO_ERROR(result, nullptr)
            //read tag
            result = SocketManager::read_data(socket, &auth_tag, &size);
            IF_IO_ERROR(result, nullptr)
            //read encrypted online users list
            result = SocketManager::read_data(socket, &ciphertext, &ciphertext_len);
            IF_IO_ERROR(result, nullptr);
            NEW(msg, new Message(), "read_message allocating message failed")
            msg->setType(USERS_LIST_RESPONSE);
            msg->setSequenceN(sequence_number);
            msg->setIv(iv);
            msg->getPayload()->setAuthTag(auth_tag);
            msg->getPayload()->setCiphertext(ciphertext);
            msg->setCTxtLen(ciphertext_len);
            break;
        case PEER_PUB_KEY:
            //read sn
            result = SocketManager::read_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, nullptr)
            //read iv
            result = SocketManager::read_data(socket, &iv, &size);
            IF_IO_ERROR(result, nullptr)
            //read tag
            result = SocketManager::read_data(socket, &auth_tag, &size);
            IF_IO_ERROR(result, nullptr)
            result = SocketManager::read_string(socket, sender);
            IF_IO_ERROR(result, nullptr)
            result = SocketManager::read_public_key(socket, &pub_key);
            IF_IO_ERROR(result, nullptr)
            NEW(msg, new Message(), "read message allocating message failed")
            msg->setType(PEER_PUB_KEY);
            msg->setSequenceN(sequence_number);
            msg->setIv(iv);
            msg->getPayload()->setAuthTag(auth_tag);
            msg->setSender(sender);
            msg->getPayload()->setPubKey(pub_key);
            break;
        case AUTH_PEER_REQUEST:
            //read sn
            result = SocketManager::read_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, nullptr)
            //read iv
            result = SocketManager::read_data(socket, &iv, &size);
            IF_IO_ERROR(result, nullptr)
            //read tag
            result = SocketManager::read_data(socket, &auth_tag, &size);
            IF_IO_ERROR(result, nullptr)
            //read nonce
            result = SocketManager::read_n(socket, sizeof(uint32_t), (void *) &nonce);
            IF_IO_ERROR(result, nullptr)
            //read sender
            result = SocketManager::read_string(socket, sender);
            IF_IO_ERROR(result, nullptr)
            //read recipient
            result = SocketManager::read_string(socket, recipient);
            IF_IO_ERROR(result, nullptr)
            NEW(msg, new Message(), "read message allocating message failed")
            msg->setType(AUTH_PEER_REQUEST);
            msg->setSequenceN(sequence_number);
            msg->setIv(iv);
            msg->getPayload()->setAuthTag(auth_tag);
            msg->getPayload()->setNonce(nonce);
            msg->setSender(sender);
            msg->setRecipient(recipient);
            break;
        case AUTH_PEER_RESPONSE:
            //read sn
            result = SocketManager::read_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, nullptr)
            //read iv
            result = SocketManager::read_data(socket, &iv, &size);
            IF_IO_ERROR(result, nullptr)
            //read tag
            result = SocketManager::read_data(socket, &auth_tag, &size);
            IF_IO_ERROR(result, nullptr)
            //read public key
            result = SocketManager::read_public_key(socket, &pub_key);
            IF_IO_ERROR(result, nullptr)
            //read signature
            result = SocketManager::read_data(socket, &signature, &signature_len);
            IF_IO_ERROR(result, nullptr)
            //read sender
            result = SocketManager::read_string(socket, sender);
            IF_IO_ERROR(result, nullptr)
            //read recipient
            result = SocketManager::read_string(socket, recipient);
            IF_IO_ERROR(result, nullptr)
            NEW(msg, new Message(), "read message allocating message failed")
            msg->setType(AUTH_PEER_RESPONSE);
            msg->setSequenceN(sequence_number);
            msg->setIv(iv);
            msg->getPayload()->setAuthTag(auth_tag);
            msg->getPayload()->setPubKey(pub_key);
            msg->getPayload()->setSignature(signature);
            msg->setSignatureLen(signature_len);
            msg->setSender(sender);
            msg->setRecipient(recipient);
            break;
        case AUTH_PEER_KEY_EX:
            //read sn
            result = SocketManager::read_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, nullptr)
            //read iv
            result = SocketManager::read_data(socket, &iv, &size);
            IF_IO_ERROR(result, nullptr)
            //read tag
            result = SocketManager::read_data(socket, &auth_tag, &size);
            IF_IO_ERROR(result, nullptr)
            //read signature
            result = SocketManager::read_data(socket, &signature, &signature_len);
            IF_IO_ERROR(result, nullptr)
            //read encrypted session key
            result = SocketManager::read_data(socket, &ciphertext, &ciphertext_len);
            IF_IO_ERROR(result, nullptr)
            //read sender
            result = SocketManager::read_string(socket, sender);
            IF_IO_ERROR(result, nullptr)
            //read recipient
            result = SocketManager::read_string(socket, recipient);
            IF_IO_ERROR(result, nullptr)
            NEW(msg, new Message(), "read message allocating message failed")
            msg->setType(AUTH_PEER_KEY_EX);
            msg->setSequenceN(sequence_number);
            msg->setIv(iv);
            msg->getPayload()->setAuthTag(auth_tag);
            msg->setSignatureLen(signature_len);
            msg->getPayload()->setSignature(signature);
            msg->setCTxtLen(ciphertext_len);
            msg->getPayload()->setCiphertext(ciphertext);
            msg->setSender(sender);
            msg->setRecipient(recipient);
            break;
        case AUTH_PEER_KEY_EX_RX:
        case DATA:
            //read server sn
            result = SocketManager::read_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, nullptr)
            //read peer sn
            result = SocketManager::read_n(socket, sizeof(uint32_t), (void *) &peer_sn);
            IF_IO_ERROR(result, nullptr)
            //read server iv
            result = SocketManager::read_data(socket, &iv, &size);
            IF_IO_ERROR(result, nullptr)
            //read peer iv
            result = SocketManager::read_data(socket, &peer_iv, &size);
            IF_IO_ERROR(result, nullptr)
            //read server tag
            result = SocketManager::read_data(socket, &auth_tag, &size);
            IF_IO_ERROR(result, nullptr)
            //read peer tag
            result = SocketManager::read_data(socket, &peer_auth_tag, &size);
            IF_IO_ERROR(result, nullptr)
            //read ciphertext
            result = SocketManager::read_data(socket, &ciphertext, &ciphertext_len);
            IF_IO_ERROR(result, nullptr)
            //read sender
            result = SocketManager::read_string(socket, sender);
            IF_IO_ERROR(result, nullptr)
            //read recipient
            result = SocketManager::read_string(socket, recipient);
            IF_IO_ERROR(result, nullptr)
            NEW(msg, new Message(), "read message allocating message failed")
            msg->setType((MESSAGE_TYPE) type);
            msg->setSequenceN(sequence_number);
            msg->setPeerSn(peer_sn);
            msg->setIv(iv);
            msg->setPeerIv(peer_iv);
            msg->setServerAuthTag(auth_tag);
            msg->getPayload()->setAuthTag(peer_auth_tag);
            msg->setCTxtLen(ciphertext_len);
            msg->getPayload()->setCiphertext(ciphertext);
            msg->setSender(sender);
            msg->setRecipient(recipient);
            break;
        case PEER_QUIT:
            //read sn
            result = SocketManager::read_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, nullptr)
            //read iv
            result = SocketManager::read_data(socket, &iv, &size);
            IF_IO_ERROR(result, nullptr)
            //read tag
            result = SocketManager::read_data(socket, &auth_tag, &size);
            IF_IO_ERROR(result, nullptr)
            //read sender
            result = SocketManager::read_string(socket, sender);
            IF_IO_ERROR(result, nullptr)
            NEW(msg, new Message(), "read message allocating message failed")
            msg->setType(PEER_QUIT);
            msg->setSequenceN(sequence_number);
            msg->setIv(iv);
            msg->getPayload()->setAuthTag(auth_tag);
            msg->setSender(sender);
            break;
        case ERROR:
            //read sn
            result = SocketManager::read_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, nullptr)
            result = SocketManager::read_n(socket, sizeof(int), (void *) &error_code);
            IF_IO_ERROR(result, nullptr)
            //read iv
            result = SocketManager::read_data(socket, &iv, &size);
            IF_IO_ERROR(result, nullptr)
            //read auth tag
            result = SocketManager::read_data(socket, &auth_tag, &size);
            IF_IO_ERROR(result, nullptr)
            NEW(msg, new Message(), "read message allocating message failed")
            msg->setType(ERROR);
            msg->setErrCode((ERROR_CODE) error_code);
            msg->getPayload()->setAuthTag(auth_tag);
            msg->setSequenceN(sequence_number);
            msg->setIv(iv);
            break;
        case CLIENT_DONE:
            //read sn
            result = SocketManager::read_n(socket, sizeof(uint32_t), (void *) &sequence_number);
            IF_IO_ERROR(result, nullptr)
            //read iv
            result = SocketManager::read_data(socket, &iv, &size);
            IF_IO_ERROR(result, nullptr)
            //read tag
            result = SocketManager::read_data(socket, &auth_tag, &size);
            IF_IO_ERROR(result, nullptr)
            //read sender
            result = SocketManager::read_string(socket, sender);
            IF_IO_ERROR(result, nullptr)
            NEW(msg, new Message(), "read message allocating message failed")
            msg->setType(CLIENT_DONE);
            msg->setSequenceN(sequence_number);
            msg->setIv(iv);
            msg->getPayload()->setAuthTag(auth_tag);
            msg->setSender(sender);
            break;
        default:
            break;
    }

    return msg;
}

int Managers::CryptoManager::gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                                         unsigned char *aad, int aad_len,
                                         unsigned char *key,
                                         unsigned char *iv, int iv_len,
        //out parameters
                                         unsigned char *ciphertext,
                                         unsigned char *tag) {
    int not_used;
    int len = 0;
    int ciphertext_len = 0;
    //create context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    OPENSSL_FAIL(ctx, "allocation cipher context failed", 0)
    //init context
    not_used = EVP_EncryptInit(ctx, CIPHER, key, iv);
    OPENSSL_FAIL(not_used, "initializing cipher failed", 0)
    //Provide any AAD data. This can be called zero or more times as required
    not_used = EVP_EncryptUpdate(ctx, nullptr, &len, aad, aad_len);
    OPENSSL_FAIL(not_used, "adding aad failed", 0);
    //encrypt plaintext
    not_used = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    OPENSSL_FAIL(not_used, "encryption failed", 0)
    //increase the ciphertext length
    ciphertext_len += len;
    //move ahead pointer
    ciphertext += len;
    //finalize encryption
    not_used = EVP_EncryptFinal(ctx, ciphertext, &len);
    OPENSSL_FAIL(not_used, "finalizing encryption fail", 0)
    //increase the ciphertext length
    ciphertext_len += len;
    //getting the tag
    not_used = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag);
    OPENSSL_FAIL(not_used, "getting authentication tag failed", 0)
    //clean up
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int Managers::CryptoManager::gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, int aad_len,
                                         unsigned char *tag, unsigned char *key, unsigned char *iv, int iv_len,
                                         unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int not_used;
    int len;
    int plaintext_len;
    int ret;
    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();
    OPENSSL_FAIL(ctx, "allocation cipher context failed", 0)
    not_used = EVP_DecryptInit(ctx, CIPHER, key, iv);
    OPENSSL_FAIL(not_used, "initializing cipher failed", 0)
    //Provide any AAD data.
    not_used = EVP_DecryptUpdate(ctx, nullptr, &len, aad, aad_len);
    OPENSSL_FAIL(not_used, "adding aad failed", 0);
    //Provide the message to be decrypted, and obtain the plaintext output.
    not_used = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    OPENSSL_FAIL(not_used, "decryption failed", 0)
    //update plaintext length
    plaintext_len = len;
    //move ahead the pointer
    plaintext += len;

    //Set expected tag value. Works in OpenSSL 1.0.1d and later
    not_used = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LEN, tag);
    OPENSSL_FAIL(not_used, "setting expected tag value failed", 0)

    // finalize decryption and compare authentication tags
    not_used = EVP_DecryptFinal(ctx, plaintext, &len);
    // cleaning up
    EVP_CIPHER_CTX_free(ctx);

    if (not_used > 0) {
        //data authenticated
        plaintext_len += len;
        return plaintext_len;
    } else {
        //tag mismatch
        return 0;
    }
}

void Managers::CryptoManager::manage_error(string message) {
    std::cerr << message << std::endl;
    ERR_print_errors_fp(stderr);
}

unsigned char *
Managers::CryptoManager::sign(unsigned char *plaintext, uint64_t plain_size, EVP_PKEY *sign_key, uint32_t *sgnt_size) {
    int not_used;
    unsigned char *sgnt_buff; //signature
    //creating signature context
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    OPENSSL_FAIL(md_ctx, "allocating signature context failed", nullptr)

    not_used = EVP_SignInit(md_ctx, DIGEST);
    OPENSSL_FAIL(not_used, "initializing signature context failed", nullptr)
    not_used = EVP_SignUpdate(md_ctx, plaintext, plain_size);
    OPENSSL_FAIL(not_used, "computing signature failed", nullptr)
    NEW(sgnt_buff, new unsigned char[EVP_PKEY_size(sign_key)], "sgnt_buff")
    //finalize signature
    not_used = EVP_SignFinal(md_ctx, sgnt_buff, sgnt_size, sign_key);
    OPENSSL_FAIL(not_used, "finalizing signature failed", nullptr)

    // delete the digest and the private key from memory:
    EVP_MD_CTX_free(md_ctx);
    return sgnt_buff;
}

int
Managers::CryptoManager::verify_signature(unsigned char *signature, uint32_t signature_size, unsigned char *plain_text,
                                          uint64_t plain_size, EVP_PKEY *pub_key) {
    int not_used;
    int result;
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    OPENSSL_FAIL(md_ctx, "allocating signature context failed", 0)
    not_used = EVP_VerifyInit(md_ctx, DIGEST);
    OPENSSL_FAIL(not_used, "initializing signature context failed", 0)
    not_used = EVP_VerifyUpdate(md_ctx, plain_text, plain_size);
    OPENSSL_FAIL(not_used, "very update failed", 0)
    result = EVP_VerifyFinal(md_ctx, signature, signature_size, pub_key);
    if (result <= 0)
        CryptoManager::manage_error("verification signature failed");
    EVP_MD_CTX_free(md_ctx);
    return result == 1 ? result : 0;
}

X509 *Managers::CryptoManager::open_certificate(string path) {
    FILE *file;
    file = fopen(path.c_str(), "r");
    if (!file) {
        cerr << "error opening " << path << endl;
        return nullptr;
    }
    X509 *cert;
    cert = PEM_read_X509(file, NULL, NULL, NULL);
    OPENSSL_FAIL(cert, "Reading cert " + path + " failed", nullptr)
    fclose(file);
    return cert;
}

X509_CRL *Managers::CryptoManager::open_crl(string path) {
    FILE *file;
    file = fopen(path.c_str(), "r");
    if (!file) {
        cerr << "error opening " << path << endl;
        return nullptr;
    }
    X509_CRL *crl;
    crl = PEM_read_X509_CRL(file, NULL, NULL, NULL);
    OPENSSL_FAIL(crl, "Reading CRL " + path + " failed", nullptr)
    fclose(file);
    return crl;

}

int Managers::CryptoManager::verify_cert(X509 *ca_cert, X509_CRL *crl, X509 *cert) {
    X509_STORE *store;
    int not_used;
    store = X509_STORE_new();
    OPENSSL_FAIL(store, "allocating store failed", 0)
    //add CA's cert
    not_used = X509_STORE_add_cert(store, ca_cert);
    OPENSSL_FAIL(not_used, "adding certificate failed", 0)
    //add crl list
    not_used = X509_STORE_add_crl(store, crl);
    OPENSSL_FAIL(not_used, "adding crl failed", 0);
    //to use crl
    not_used = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    OPENSSL_FAIL(not_used, "setting clr flag fail", 0)

    //certificate verification
    X509_STORE_CTX *ctx_store = X509_STORE_CTX_new();
    OPENSSL_FAIL(ctx_store, "allocating store context failed", 0)
    //init store context
    not_used = X509_STORE_CTX_init(ctx_store, store, cert, NULL);
    OPENSSL_FAIL(not_used, "initializing ctx_store failed", 0)
    //verify cert
    int result = 0;
    result = X509_verify_cert(ctx_store);
    //clean up
    X509_STORE_free(store);
    X509_STORE_CTX_free(ctx_store);

    return result == 1 ? result : 0;
}

int Managers::CryptoManager::generate_random_bytes(unsigned char *bytes, int amount) {
    static uint32_t times = 0;
    int not_used;
    //reseed
    if (times >= numeric_limits<uint32_t>::max() - 1) {
        not_used = RAND_poll();
        OPENSSL_FAIL(not_used, "polling error", 0);
        times = 0;
    }
    not_used = RAND_bytes(bytes, amount);
    if (not_used == -1) {
        cerr << "RAND_bytes() is not supported" << endl;
        return 0;
    }
    OPENSSL_FAIL(not_used, "generating rand bytes failed", 0)
    return 1;
}

int Managers::CryptoManager::generate_nonce(uint32_t *nonce) {
    int result;
    unsigned char *bytes;
    NEW(bytes, new unsigned char[4], "bytes nonce")
    result = CryptoManager::generate_random_bytes(bytes, 4);
    if (result)
        *nonce = (uint32_t) ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]);
    delete[] bytes;
    return result;
}

int Managers::CryptoManager::generate_ephemeral_rsa(EVP_PKEY **pub_key, EVP_PKEY **pvt_key) {
    int not_used;
    RSA *key_pair;
    BIGNUM *e;
    //use bio buffer to store RSA parameter
    BIO *pub_key_stream;
    BIO *pvt_key_stream;
    char *pvt_key_bytes;
    char *pub_key_bytes;
    BIO *bio_buff_pub_key;
    BIO *bio_buff_pvt_key;
    RSA *tmp_pub_key = nullptr;
    RSA *tmp_pvt_key = nullptr;

    key_pair = RSA_new();
    OPENSSL_FAIL(key_pair, "allocating ephemeral keys failed", 0)
    e = BN_new();
    OPENSSL_FAIL(e, "allocating e failed", 0)
    BN_set_word(e, RSA_F4);
    //seed before generating ephemeral key pair
    RAND_poll();
    not_used = RSA_generate_key_ex(key_pair, RSA_SIZE, e, nullptr);
    OPENSSL_FAIL(not_used, "generating rsa keys failed", 0)
    //create bio buffers
    pub_key_stream = BIO_new(BIO_s_mem());
    pvt_key_stream = BIO_new(BIO_s_mem());
    //write public and private key in PEM format into bio
    OPENSSL_FAIL(pub_key_stream && pvt_key_stream, "allocating key buffers failed ", 0)
    not_used = PEM_write_bio_RSAPublicKey(pub_key_stream, key_pair);
    OPENSSL_FAIL(not_used, "writing public key over bio stream failed", 0)
    not_used = PEM_write_bio_RSAPrivateKey(pvt_key_stream, key_pair, NULL, NULL, 0, NULL, NULL);
    OPENSSL_FAIL(not_used, "writing private key over bio stream failed", 0)
    //get keys size
    auto size_public_key = BIO_pending(pub_key_stream);
    auto size_private_key = BIO_pending(pvt_key_stream);
    NEW(pub_key_bytes, new char[size_public_key], "pub_key_bytes")
    NEW(pvt_key_bytes, new char[size_private_key], "pub_key_bytes")
    //put keys form bio streams into char buffers
    not_used = BIO_read(pub_key_stream, pub_key_bytes, size_public_key);
    OPENSSL_FAIL(not_used, "moving public key from bio stream failed", 0)
    not_used = BIO_read(pvt_key_stream, pvt_key_bytes, size_private_key);
    OPENSSL_FAIL(not_used, "moving private key from bio stream failed", 0)
    //from keys in PEM format to EVP_PKEY
    bio_buff_pub_key = BIO_new_mem_buf((void *) pub_key_bytes, size_public_key);
    OPENSSL_FAIL(bio_buff_pub_key, "allocating bio_buff_pub_key failed", 0)
    bio_buff_pvt_key = BIO_new_mem_buf((void *) pvt_key_bytes, size_private_key);
    OPENSSL_FAIL(bio_buff_pvt_key, "allocating bio_buff_pvt_key failed", 0)
    //get the RSA key from bio memory buffers
    tmp_pub_key = PEM_read_bio_RSAPublicKey(bio_buff_pub_key, &tmp_pub_key, NULL, NULL);
    OPENSSL_FAIL(tmp_pub_key, "reading tmp_pub_key failed", 0)
    tmp_pvt_key = PEM_read_bio_RSAPrivateKey(bio_buff_pvt_key, &tmp_pvt_key, NULL, NULL);
    OPENSSL_FAIL(tmp_pvt_key, "reading tmp_pvt_key failed", 0)
    //put keys into EVP_PKEY to work with OpenSSL
    not_used = EVP_PKEY_assign_RSA(*pub_key, tmp_pub_key);
    OPENSSL_FAIL(not_used, "putting public key into EVP data structure failed", 0)
    not_used = EVP_PKEY_assign_RSA(*pvt_key, tmp_pvt_key);
    OPENSSL_FAIL(not_used, "putting private key into EVP data structure failed", 0)
    //cleaning up
    RSA_free(key_pair);
    BN_free(e);
    BIO_free(pub_key_stream);
    BIO_free(pvt_key_stream);
    BIO_free_all(bio_buff_pub_key);
    BIO_free_all(bio_buff_pvt_key);
    delete[] pub_key_bytes;
    delete[] pvt_key_bytes;
    return 1;
}

unsigned char *Managers::CryptoManager::sign_pubKey(EVP_PKEY *pubkey, EVP_PKEY *pvtkey, uint32_t nonce,
                                                    uint32_t *signature_size) {
    unsigned char *signature;
    int not_used;
    BIO *stream = BIO_new(BIO_s_mem());
    OPENSSL_FAIL(stream, "allocating bio stream failed", nullptr)
    not_used = PEM_write_bio_PUBKEY(stream, pubkey);
    OPENSSL_FAIL(not_used, "writing pubkey on bio stream failed", nullptr);
    not_used = BIO_write(stream, (void *) &nonce, sizeof(uint32_t));
    OPENSSL_FAIL(not_used, "writing nonce on bio stream failed", nullptr);
    int plain_size = BIO_pending(stream);
    unsigned char *plain_text;
    NEW(plain_text, new unsigned char[plain_size], "plain_text")
    not_used = BIO_read(stream, (void *) plain_text, plain_size);
    OPENSSL_FAIL(not_used, "reading from bio stream failed", nullptr);
    signature = CryptoManager::sign(plain_text, plain_size, pvtkey, signature_size);
    //cleaning up
    BIO_free(stream);
    delete[] plain_text;
    return signature;
}

int Managers::CryptoManager::verify_signed_pubKey(EVP_PKEY *pubkey_signed, uint32_t nonce, EVP_PKEY *pubkey,
                                                  unsigned char *signature, uint32_t signature_size) {
    int not_used;
    BIO *stream = BIO_new(BIO_s_mem());
    OPENSSL_FAIL(stream, "allocating bio stream failed", 0)
    not_used = PEM_write_bio_PUBKEY(stream, pubkey_signed);
    OPENSSL_FAIL(not_used, "writing pubkey on bio stream failed", 0);
    not_used = BIO_write(stream, (void *) &nonce, sizeof(uint32_t));
    OPENSSL_FAIL(not_used, "writing nonce on bio stream failed", 0);
    int plain_size = BIO_pending(stream);
    unsigned char *plain_text;
    NEW(plain_text, new unsigned char[plain_size], "plain_text")
    not_used = BIO_read(stream, (void *) plain_text, plain_size);
    OPENSSL_FAIL(not_used, "reading from bio stream failed", 0);
    not_used = CryptoManager::verify_signature(signature, signature_size, plain_text, plain_size, pubkey);
    BIO_free(stream);
    delete[] plain_text;
    return not_used;
}

unsigned char *Managers::CryptoManager::compute_hash(unsigned char *bytes, size_t size, uint32_t *digest_len) {
    unsigned char *digest;
    EVP_MD_CTX *ctx;
    int not_used;
    NEW(digest, new unsigned char[EVP_MD_size(DIGEST)], "digest compute hash")
    ctx = EVP_MD_CTX_new();
    OPENSSL_FAIL(ctx, "allocating digest ctx failed", nullptr)
    not_used = EVP_DigestInit(ctx, DIGEST);
    OPENSSL_FAIL(not_used, "initializing hash ctx failed", nullptr)
    not_used = EVP_DigestUpdate(ctx, bytes, size);
    OPENSSL_FAIL(not_used, "updating hash ctx failed", nullptr)
    not_used = EVP_DigestFinal(ctx, digest, digest_len);
    EVP_MD_CTX_free(ctx);
    OPENSSL_FAIL(not_used, "finalizing hash ctx failed", nullptr)
    return digest;
}

unsigned char *Managers::CryptoManager::compute_session_key(unsigned char *master_secret, size_t ms_size) {
    unsigned char *session_key;
    unsigned char *digest;
    uint32_t digest_len = 0;
    digest = CryptoManager::compute_hash(master_secret, ms_size, &digest_len);
    OPENSSL_FAIL(digest, "computing digest failed", nullptr)
    NEW(session_key, new unsigned char[KEY_LENGTH], "session_key compute")
    memmove(session_key, digest, KEY_LENGTH);
    delete[] digest;
    return session_key;
}

//do not allocate ciphertext buffer
int Managers::CryptoManager::rsa_encrypt(unsigned char **ciphertext, size_t *ciphertext_len, unsigned char *plaintext,
                                         uint32_t plain_size, EVP_PKEY *pub_key) {
    EVP_PKEY_CTX *ctx;
    ENGINE *eng;
    int not_used;

    RSA *r = EVP_PKEY_get0_RSA(pub_key);
    OPENSSL_FAIL(r, "EVP_PKEY_get0_RSA", 0);
    NEW(*ciphertext, new unsigned char[RSA_size(r)], "ciphertext")
    not_used = RSA_public_encrypt(plain_size, plaintext, *ciphertext, r, RSA_PKCS1_PADDING);
    if (not_used < 0) {
        CryptoManager::manage_error("RSA_public_encrypt");
        return 0;
    }
    OPENSSL_FAIL(not_used, "rsa encryption failed", 0)
    *ciphertext_len = not_used;
    return 1;
}

//do not allocate plaintext buffer
int Managers::CryptoManager::rsa_decrypt(unsigned char *ciphertext, size_t ciphertext_len, unsigned char **plaintext,
                                         size_t *plain_size, EVP_PKEY *pvt_key) {
    EVP_PKEY_CTX *ctx;
    ENGINE *eng;
    int not_used;
    RSA *r = EVP_PKEY_get0_RSA(pvt_key);
    OPENSSL_FAIL(r, "EVP_PKEY_get0_RSA", 0);
    NEW(*plaintext, new unsigned char[RSA_size(r)], "plaintext")
    not_used = RSA_private_decrypt(ciphertext_len, ciphertext, *plaintext, r, RSA_PKCS1_PADDING);
    if (not_used < 0) {
        CryptoManager::manage_error("RSA_private_decrypt");
        return 0;
    }
    OPENSSL_FAIL(not_used, "rsa encryption failed", 0)
    *plain_size = not_used;
    return 1;

}

int Managers::CryptoManager::pkey_to_bytes(EVP_PKEY *pkey, unsigned char **pkey_bytes, uint32_t *bytes_size) {
    int result = 0;
    BIO *stream = BIO_new(BIO_s_mem());
    OPENSSL_FAIL(stream, "allocating bio stream failed", 0)
    result = PEM_write_bio_PUBKEY(stream, pkey);
    OPENSSL_FAIL(result, "writing pubkey on bio stream failed", 0);
    long size = BIO_pending(stream);
    NEW(*pkey_bytes, new unsigned char[size], "pkey_bytes")
    result = BIO_read(stream, (void *) *pkey_bytes, size);
    OPENSSL_FAIL(result, "reading pkey_bytes failed", 0)
    *bytes_size = size;
    BIO_free(stream);
    return 1;
}

unsigned char *Managers::CryptoManager::generate_iv() {
    unsigned char *iv;
    int not_used;
    size_t len = IV_LEN;
    NEW(iv, new unsigned char[len], "iv")
    not_used = CryptoManager::generate_random_bytes(iv, len);
    IF_MANAGER_FAILED(not_used, "generate iv failed", nullptr);
    return iv;
}

int
Managers::CryptoManager::authenticate_data(unsigned char *aad, uint32_t aad_len, unsigned char *iv, unsigned char *key,
                                           unsigned char *tag) {
    int not_used;
    int len = 0;
    unsigned char *ciphertex;
    //create context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    OPENSSL_FAIL(ctx, "allocation cipher context failed", 0)
    //init context
    not_used = EVP_EncryptInit(ctx, CIPHER, key, iv);
    OPENSSL_FAIL(not_used, "initializing cipher failed", 0)
    not_used = EVP_EncryptUpdate(ctx, nullptr, &len, aad, aad_len);
    OPENSSL_FAIL(not_used, "adding aad failed", 0);
    not_used = EVP_EncryptFinal(ctx, ciphertex, &len);
    OPENSSL_FAIL(not_used, "encryption failed", 0)
    not_used = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag);
    OPENSSL_FAIL(not_used, "getting authentication tag failed", 0)
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int Managers::CryptoManager::verify_auth_data(unsigned char *aad, uint32_t aad_len, unsigned char *iv,
                                              unsigned char *key, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int not_used;
    int len;
    int plaintext_len;
    unsigned char *plaintext;
    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();
    OPENSSL_FAIL(ctx, "allocation cipher context failed", 0)
    not_used = EVP_DecryptInit(ctx, CIPHER, key, iv);
    OPENSSL_FAIL(not_used, "initializing cipher failed", 0)
    //Provide any AAD data.
    not_used = EVP_DecryptUpdate(ctx, nullptr, &len, aad, aad_len);
    OPENSSL_FAIL(not_used, "adding aad failed", 0);
    //Set expected tag value. Works in OpenSSL 1.0.1d and later
    not_used = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LEN, tag);
    OPENSSL_FAIL(not_used, "setting expected tag value failed", 0)
    // finalize decryption and compare authentication tags
    not_used = EVP_DecryptFinal(ctx, plaintext, &len);
    // cleaning up
    EVP_CIPHER_CTX_free(ctx);
    return not_used > 0;

}

int Managers::CryptoManager::message_to_bytes(Message *message, unsigned char **bytes) {
    size_t len;
    int not_used;
    unsigned char *sn = uint32_to_bytes(message->getSequenceN());
    BIO *bio = BIO_new(BIO_s_mem());
    OPENSSL_FAIL(bio, "allocating bio stream message to bytes failed", 0)
    switch (message->getType()) {
        case AUTH_KEY_EXCHANGE_RESPONSE:
            not_used = BIO_write(bio, sn, sizeof(uint32_t));
            BIO_FAIL(not_used, "message_to_bytest writing sn 0", 0);
            not_used = BIO_write(bio, message->getIv(), IV_LEN);
            BIO_FAIL(not_used, "message_to_bytes wrinting IV failed 0", 0);
            break;
        case REQUEST_TO_TALK:
        case REQUEST_OK:
        case REQUEST_KO:
            not_used = BIO_write(bio, message->getSender().c_str(), message->getSender().length());
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 1", 0)
            not_used = BIO_write(bio, message->getRecipient().c_str(), message->getRecipient().length());
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 2", 0)
            not_used = BIO_write(bio, sn, sizeof(uint32_t));
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 3", 0)
            not_used = BIO_write(bio, message->getIv(), IV_LEN);
            OPENSSL_FAIL(not_used, "message_to_bytes writing bio stream failed 4", 0)
            break;
        case USERS_LIST:
            not_used = BIO_write(bio, message->getSender().c_str(), message->getSender().length());
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 5", 0)
            not_used = BIO_write(bio, sn, sizeof(uint32_t));
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 6", 0)
            not_used = BIO_write(bio, message->getIv(), IV_LEN);
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 7", 0)
            break;
        case USERS_LIST_RESPONSE:
            not_used = BIO_write(bio, sn, sizeof(uint32_t));
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 8", 0)
            not_used = BIO_write(bio, message->getIv(), IV_LEN);
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 9", 0)
            break;
        case PEER_PUB_KEY:
            not_used = BIO_write(bio, sn, sizeof(uint32_t));
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 10", 0)
            not_used = BIO_write(bio, message->getIv(), IV_LEN);
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 11 ", 0)
            not_used = PEM_write_bio_PUBKEY(bio, message->getPayload()->getPubKey());
            OPENSSL_FAIL(not_used, "message_to_bytes writing pub key failed 12", 0)
            not_used = BIO_write(bio, message->getSender().c_str(), message->getSender().length());
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 13", 0)
            break;
        case AUTH_PEER_REQUEST:
            not_used = BIO_write(bio, sn, sizeof(uint32_t));
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 14", 0)
            not_used = BIO_write(bio, message->getIv(), IV_LEN);
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 15", 0)
            not_used = BIO_write(bio, message->getSender().c_str(), message->getSender().length());
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 16", 0)
            not_used = BIO_write(bio, message->getRecipient().c_str(), message->getRecipient().length());
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 17", 0)
            break;
        case AUTH_PEER_RESPONSE:
            not_used = BIO_write(bio, sn, sizeof(uint32_t));
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 18", 0)
            not_used = BIO_write(bio, message->getIv(), IV_LEN);
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 19", 0)
            not_used = PEM_write_bio_PUBKEY(bio, message->getPayload()->getPubKey());
            OPENSSL_FAIL(not_used, "message_to_bytes writing pub key failed 20", 0)
            not_used = BIO_write(bio, message->getSender().c_str(), message->getSender().length());
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 21", 0)
            not_used = BIO_write(bio, message->getRecipient().c_str(), message->getRecipient().length());
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 22", 0)
            break;
        case AUTH_PEER_KEY_EX:
            not_used = BIO_write(bio, sn, sizeof(uint32_t));
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 23", 0)
            not_used = BIO_write(bio, message->getIv(), IV_LEN);
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 24", 0)
            not_used = BIO_write(bio, message->getPayload()->getSignature(), message->getSignatureLen());
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 25", 0)
            not_used = BIO_write(bio, message->getPayload()->getCiphertext(), message->getCTxtLen());
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 26", 0)
            not_used = BIO_write(bio, message->getSender().c_str(), message->getSender().length());
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 27", 0)
            not_used = BIO_write(bio, message->getRecipient().c_str(), message->getRecipient().length());
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 28", 0)
            break;
        case AUTH_PEER_KEY_EX_RX:
        case DATA:
            not_used = BIO_write(bio, sn, sizeof(uint32_t));
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 29", 0)
            not_used = BIO_write(bio, message->getIv(), IV_LEN);
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 30", 0)
            not_used = BIO_write(bio, message->getPayload()->getCiphertext(), message->getCTxtLen());
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 31", 0)
            not_used = BIO_write(bio, message->getSender().c_str(), message->getSender().length());
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 32", 0)
            not_used = BIO_write(bio, message->getRecipient().c_str(), message->getRecipient().length());
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 33", 0)
            break;
        case PEER_QUIT:
            not_used = BIO_write(bio, sn, sizeof(uint32_t));
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 34", 0)
            not_used = BIO_write(bio, message->getIv(), IV_LEN);
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 35", 0)
            not_used = BIO_write(bio, message->getSender().c_str(), message->getSender().length());
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed", 0)
            break;
        case ERROR:
            not_used = BIO_write(bio, sn, sizeof(uint32_t));
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 36", 0)
            not_used = BIO_write(bio, message->getIv(), IV_LEN);
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 37", 0)
            break;
        case CLIENT_DONE:
            not_used = BIO_write(bio, sn, sizeof(uint32_t));
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 36", 0)
            not_used = BIO_write(bio, message->getIv(), IV_LEN);
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 37", 0)
            not_used = BIO_write(bio, message->getSender().c_str(), message->getSender().length());
            BIO_FAIL(not_used, "message_to_bytes writing bio stream failed 32", 0)
            break;
        default:
            break;
    }
    delete[] sn;
    len = BIO_pending(bio);
    NEW(*bytes, new unsigned char[len], "message to bytes allocating buffer failed")
    not_used = BIO_read(bio, *bytes, len);
    BIO_free(bio);
    BIO_FAIL(not_used, "message to bytes reading message byte failed", 0)
    return len;
}