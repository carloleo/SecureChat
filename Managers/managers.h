//
// Created by crl on 2/24/22.
//

#ifndef SECURECHAT_MANAGERS_H
#define SECURECHAT_MANAGERS_H

#include <string>
#include "../Common/Message.h"
#include <openssl/evp.h>
#include <cstddef>
// Crypto constants: modify them to change the cipher suite
#define CIPHER  EVP_aes_128_gcm()
#define DIGEST EVP_sha256()
#define RSA_SIZE 2048
#define TAG_LEN 16
#define IV_LEN EVP_CIPHER_iv_length(CIPHER)
#define BLOCK_SIZE EVP_CIPHER_block_size(CIPHER)

/*
 * Library providing network and cryptographic functions
 */
namespace Managers {
    // Network functions
    namespace SocketManager {
        /*
         * @brief: write amount bytes being stored in buff to socket
         * @return: 1 on success
         */
        int write_n(int socket, size_t amount, void *buff);

        /*
         * @brief: read amount bytes from socket and store them into buff
         * @return: 1 on success
         */
        int read_n(int socket, size_t amount, void *buff);

        /*
         * @brief: send msg to socket
         * @return: 1 on success
         */
        int send_message(int socket, Message *msg);

        /*
         * @brief: write str on socket
         * @return: 1 on success
         */
        int write_string(int socket, std::string str);

        /*
         * @brief: read a message form socket
         * @return: pointer to message object on success nullptr on error
         */
        Message *read_message(int socket);

        /*
         * @brief: read a string from socket and store it into str
         * @return: 1 on success
         */
        int read_string(int socket, std::string &str);

        /*
         * @brief: send cert to socket
         * @return: 1 on success
         */
        int send_certificate(int socket, X509 *cert);

        /*
         * @brief: send pubkey to socket
         * @return: 1 on success
         */
        int send_public_key(int socket, EVP_PKEY *pubkey);

        /*
         * @brief: send len data to socket
         * @return: 1 on success
         */
        int send_data(int socket, unsigned char *data, uint32_t len);

        /*
         * @brief: read len bytes and store them into data
         * @return: 1 on success
         */
        int read_data(int socket, unsigned char **data, uint32_t *len);

        /*
         * @brief: read X509 certificate from socket and store it into cert
         * @return: 1 on success
         */
        int read_certificate(int socket, X509 **cert);

        /*
         * @brief: read public key from socket and store it into pubkey
         * @return: 1 on success
         */
        int read_public_key(int socket, EVP_PKEY **pubkey);

        /*
         * @brief: encrypt body by CryptoManager::gcm_encrypt(), set sequence_number and send it to socket w.r.t type
         * @return: 1 on success
         */
        int send_encrypted_message(int socket, uint32_t sequence_number, unsigned char *session_key,
                                   std::string body, MESSAGE_TYPE type);

        /*
         * @brief: authenticate message by CryptoManager::authenticate_data(), set the authentication tag and send it to socket
         * @param: for_peer true in case the final receiver is another user
         * @return: 1 on success
         */
        int send_authenticated_message(int socket, Message *message, unsigned char *key, bool for_peer = false);


    }
    //Cryptographic functions
    namespace CryptoManager {
        /*
         * @brief: encrypt plaintext by AES in gcm mode
         * @param: aad additional authenticated data
         * @param: aad_len aad length
         * @param: key encryption key
         * @param: iv initialization vector
         * @param: iv_len iv length
         * @param: ciphertext storing the encrypted plaintext
         * @param: tag storing the authentication tag
         * @return: 1 on success
         */
        int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                        unsigned char *aad, int aad_len,
                        unsigned char *key,
                        unsigned char *iv, int iv_len,
                        unsigned char *ciphertext,
                        unsigned char *tag);

        /*
         * @brief: decrypt ciphertext by AES in gcm mode
         * @param: aad additional authenticated data
         * @param: aad_len aad length
         * @param: tag authentication tag to be verified
         * @param: key decryption key
         * @param: iv initialization vector
         * @param: iv_len iv length
         * @param: plaintext storing the decrypted ciphertext
         * @return: 1 on success
         */
        int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                        unsigned char *aad, int aad_len,
                        unsigned char *tag,
                        unsigned char *key,
                        unsigned char *iv, int iv_len,
                        unsigned char *plaintext);

        /*
         * @brief: sign plaintext by RSA 2048-bit
         * @param: plain_size plaintext size
         * @param: sign_key RSA private key
         * @param: sgnt_size storing the signature size
         * @return: pointer to the signature on success nullptr on error
         */
        unsigned char *sign(unsigned char *plaintext, uint64_t plain_size, EVP_PKEY *sign_key, uint32_t *sgnt_size);

        /*
         * @brief: verify signature by RSA 2048-bit
         * @param: signature_size signature size
         * @param: plain_text data being signed
         * @param: plain_size data being signed size
         * @param: pub_key RSA public key
         * @return: 1 on success
         */
        int verify_signature(unsigned char *signature, uint32_t signature_size, unsigned char *plain_text, uint64_t
        plain_size, EVP_PKEY *pub_key);

        /*
         * @brief: sign pubkey by RSA 2048-bit
         * @param: pvykey RSA private key
         * @param: nonce
         * @param: signature_size signature length
         * @return: pointer to the signature on success nullptr on error
         */
        unsigned char *sign_pubKey(EVP_PKEY *pubkey, EVP_PKEY *pvtkey, uint32_t nonce, uint32_t *signature_size);

        /*
         * @brief: compute SHA-256 on bytes
         * @param: size bytes size
         * @param: digest_len storing the digest size
         * @return: pointer to the digest on success nullptr on error
         */
        unsigned char *compute_hash(unsigned char *bytes, size_t size, uint32_t *digest_len);

        /*
         * @brief: derive a session key from master_secret by computing SHA-256
         * @param: ms_size master_secret size
         */
        unsigned char *compute_session_key(unsigned char *master_secret, size_t ms_size);

        /*
         * @brief: verify signature on pubkey_signed
         * @param: nonce
         * @param: pubkey RSA public key
         * @param: signature to be verified
         * @param: signature_size signature size
         * @return: 1 on success
         */
        int verify_signed_pubKey(EVP_PKEY *pubkey_signed, uint32_t nonce, EVP_PKEY *pubkey,
                                 unsigned char *signature, uint32_t signature_size);

        /*
         * @brief: open X509 certificate at path
         * @return: pointer to X509 object on success nullptr on error
         */
        X509 *open_certificate(std::string path);

        /*
         * @brief: open CRL at path
         * @return: pointer to X509_CRL object on success nullptr on error
         */
        X509_CRL *open_crl(std::string path);

        /*
         * @brief: verify authenticity of cert
         * @param: ca_cert Certification Authority certificate
         * @param: crl Certificate Revocation List
         * @return: 1 on success
         */
        int verify_cert(X509 *ca_cert, X509_CRL *crl, X509 *cert);

        /*
         * @brief: print OPENSSL error by adding message
         */
        void manage_error(std::string message);

        /*
         * @brief: generate amount pseudo-random bytes
         * @param: bytes storing generated bytes
         * @return: 1 on success
         */
        int generate_random_bytes(unsigned char *bytes, int amount);

        /*
         * @brief: generate nonce
         * @param: nonce storing the generated one
         * @return: 1 on success
         */
        int generate_nonce(uint32_t *nonce);

        /*
         * @brief: generate ephemeral RSA 2048-bit keys
         * @param: pub_key storing the generated public key
         * @param: pvt_key storing the generated private key
         * @return: 1 on success
         */
        int generate_ephemeral_rsa(EVP_PKEY **pub_key, EVP_PKEY **pvt_key);

        /*
         * @brief: encrypt plaintext by RSA 2048-bit
         * @param: ciphertext storing the encrypted plaintext
         * @param: ciphertext_len ciphertext length
         * @param: plain_size plaintext length
         * @param: pub_key RSA 2048-bit public key
         * @return: 1 on success
         */
        int rsa_encrypt(unsigned char **ciphertext, size_t *ciphertext_len, unsigned char *plaintext,
                        uint32_t plain_size, EVP_PKEY *pub_key);

        /*
        * @brief: decrypt ciphertext by RSA 2048-bit
        * @param: ciphertext_len ciphertext length
        * @param: plaintext storing the decrypted ciphertext
        * @param: ciphertext_len ciphertext length
        * @param: plain_size plaintext length
        * @param: pvt_key RSA 2048-bit private key
        * @return: 1 on success
        */
        int rsa_decrypt(unsigned char *ciphertext, size_t ciphertext_len, unsigned char **plaintext,
                        size_t *plain_size, EVP_PKEY *pvt_key);

        /*
         * @brief: write pkey into pkey_bytes
         * @param: bytes_size storing how many bytes has been written
         * @return: 1 on success
         */
        int pkey_to_bytes(EVP_PKEY *pkey, unsigned char **pkey_bytes, uint32_t *bytes_size);

        /*
         * @brief: generate initialization vector for CIPHER
         * @return: pointer to the IV on success nullptr on error
         */
        unsigned char *generate_iv();

        /*
         * @brief: authenticate aad
         * @param: aad_len aad length
         * @param: iv initialization vector
         * @param: key CIPHER key
         * @param: tag storing the authentication tag
         * @return: 1 on success
         */
        int authenticate_data(unsigned char *aad, uint32_t aad_len, unsigned char *iv, unsigned char *key,
                              unsigned char *tag);

        /*
         * @brief: verify aad authenticity
         * @param: aad_len aad length
         * @param: iv initialization vector
         * @param: key CIPHER key
         * @param: tag authentication tag
         * @return: 1 on success
         */
        int verify_auth_data(unsigned char *aad, uint32_t aad_len, unsigned char *iv, unsigned char *key,
                             unsigned char *tag);

        /*
         * @brief: write message into bytes w.r.t its type
         * @return: 1 on success
         */
        int message_to_bytes(Message *message, unsigned char **bytes);
    }
}


#endif //SECURECHAT_MANAGERS_H
