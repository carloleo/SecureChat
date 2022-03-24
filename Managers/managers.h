//
// Created by crl on 2/24/22.
//

#ifndef SECURECHAT_MANAGERS_H
#define SECURECHAT_MANAGERS_H
#include <string>
#include "../Common/Message.h"
#include <openssl/evp.h>
#include <cstddef>
#define CIPHER  EVP_aes_128_gcm()
#define DIGEST EVP_sha256()
#define RSA_SIZE 2048
#define TAG_LEN 16
#define IV_LEN EVP_CIPHER_iv_length(CIPHER)
namespace Managers {
    namespace SocketManager {
        int write_n(int socket, size_t amount, void* buff);
        int read_n(int socket, size_t amount, void* buff);
        int send_message(int socket,Message* msg);
        int write_string(int socket, std::string str);
        Message* read_message(int socket);
        int read_string(int socket, std::string &str);
        int send_certificate(int socket, X509* cert);
        int send_public_key(int socket, EVP_PKEY* pubkey);
        int send_data(int socket,unsigned char* data, uint32_t len);
        int read_data(int socket,unsigned char** data, uint32_t *len);
        int read_certificate(int socket, X509** cert);
        int read_public_key(int socket, EVP_PKEY** pubkey);
        int send_encrypted_message(int socket, uint32_t sequence_number, unsigned char*session_key,
                               std::string body, MESSAGE_TYPE type);
        int send_authenticated_message(int socket, Message* message,unsigned char *key);


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
        unsigned char* sign_pubKey(EVP_PKEY *pubkey,EVP_PKEY *pvtkey,uint32_t nonce, uint32_t* signature_size);
        unsigned char* compute_hash(unsigned char *bytes,size_t size,uint32_t* digest_len) ;
        unsigned char* compute_session_key(unsigned char* master_secret,size_t ms_size);
        int verify_signed_pubKey(EVP_PKEY *pubkey_signed, uint32_t nonce, EVP_PKEY *pubkey,
                                 unsigned  char* signature, uint32_t signature_size);
        X509* open_certificate(std::string path);
        X509_CRL* open_crl(std::string path);
        int verify_cert(X509* ca_cert, X509_CRL* crl, X509* cert) ;
        void manage_error(std::string message);
        int generate_random_bytes(unsigned char* bytes,int amount);
        int generate_nonce(uint32_t* nonce);
        int generate_ephemeral_rsa(EVP_PKEY**pub_key, EVP_PKEY**pvt_key);
        int rsa_encrypt(unsigned char** ciphertext, size_t* ciphertext_len, unsigned char* plaintext,
                        uint32_t plain_size,EVP_PKEY* pub_key);
        int rsa_decrypt(unsigned char* ciphertext, size_t ciphertext_len, unsigned char** plaintext,
                        size_t* plain_size,EVP_PKEY* pvt_key);
        int pkey_to_bytes(EVP_PKEY* pkey,unsigned char** pkey_bytes, uint32_t* bytes_size);
        unsigned char* generate_iv();
        int authenticate_data(unsigned char* aad, uint32_t aad_len,unsigned char* iv, unsigned char*key,
                              unsigned char* tag);
        int verify_auth_data(unsigned char* aad, uint32_t aad_len,unsigned char* iv, unsigned char*key,
                              unsigned char* tag);
        int message_to_bytes(Message* message, unsigned char** bytes);
    }
}


#endif //SECURECHAT_MANAGERS_H
