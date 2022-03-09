//
// Created by crl on 2/24/22.
//

#ifndef SECURECHAT_MANAGERS_H
#define SECURECHAT_MANAGERS_H
#include <string>
#include "../Common/Message.h"
#include <openssl/evp.h>
#include <cstddef>
namespace Managers {
    namespace SocketManager {
        int write_n(int socket, size_t amount, void* buff);
        int read_n(int socket, size_t amount, void* buff);
        int send_message(int socket,Message* msg);
        Message* read_message(int socket);

    }
    namespace CryptoManager {
        int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                        unsigned char *aad, int aad_len,
                        unsigned char *key,
                        unsigned char *iv, int iv_len,
                        unsigned char *ciphertext,
                        unsigned char *tag);
        int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                        unsigned char *aad, int aad_len,
                        unsigned char *tag,
                        unsigned char *key,
                        unsigned char *iv, int iv_len,
                        unsigned char *plaintext);
        unsigned char* sign(unsigned char*plaintext, uint64_t plain_size , EVP_PKEY* sign_key,uint32_t* sgnt_size);
        int verify_signature(unsigned  char*signature, uint32_t  signature_size, unsigned  char* plain_text, uint64_t
                                plain_size, EVP_PKEY* pub_key);
        X509* open_certificate(std::string path);
        X509_CRL* open_crl(std::string path);
        int verify_cert(X509* ca_cert, X509_CRL* crl, X509* cert) ;
        void manage_error(std::string message);
        int generate_random_bytes(unsigned char* bytes,int amount);
        int generate_nonce(uint32_t* nonce);
    }
}


#endif //SECURECHAT_MANAGERS_H
