//
// Created by crl on 2/24/22.
//

#ifndef SECURECHAT_MANAGERS_H
#define SECURECHAT_MANAGERS_H
#include <string>
#include <openssl/evp.h>
#include <cstddef>
namespace Managers {
    namespace SocketManager {
        int write_n(int socket, size_t amount, void* buff);
        int read_n(int socket, size_t amount, void* buff);

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
        bool verify_signature(unsigned  char*signature, EVP_PKEY* pub_key);
        void manage_error(std::string message);
    }
}


#endif //SECURECHAT_MANAGERS_H
