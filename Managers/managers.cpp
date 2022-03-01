//
// Created by crl on 2/24/22.
//

#include "managers.h"
#include <csignal>
#include <cerrno>
#include <openssl/evp.h>
#include <iostream>
#include <string>

#define CIPHER  EVP_aes_128_gcm()
#define TAG_LEN 16

using namespace std;
int Managers::SocketManager::write_n(int socket, size_t amount, void *buff) {
    size_t tot = 0;
    size_t n;
    while (tot < amount){
        n = write(socket,buff,amount);
        if(n == -1 && errno != EINTR)
            return -1;
        else if(errno == EINTR)
            continue;
        tot += n;
    }
    return 1;
}
int Managers::SocketManager::read_n(int socket, size_t amount, void *buff) {
    size_t tot = 0;
    size_t n;
    while (tot < amount){
        n = read(socket,buff,amount);
        if(n == -1 && errno != EINTR)
            return -1;
        else if(errno == EINTR)
            continue;
        tot += n;
    }
    return 1;
}

int Managers::CryptoManager::gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                                         unsigned char *aad, int aad_len,
                                         unsigned char *key,
                                         unsigned char *iv, int iv_len,
                                         //out parameters
                                         unsigned char *ciphertext,
                                         unsigned char *tag){
    int not_used;
    int len=0;
    int ciphertext_len = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx){
        CryptoManager::manage_error("allocation cipher context failed");
        return 0;
    }
    not_used = EVP_EncryptInit(ctx,CIPHER,key,iv);
    if(not_used != 1){
        CryptoManager::manage_error("initializing cipher failed");
        return 0;
    }

    //Provide any AAD data. This can be called zero or more times as required
    not_used = EVP_EncryptUpdate(ctx, nullptr, &len, aad, aad_len);
    if(not_used != 1 ) {
        CryptoManager::manage_error("adding aad failed");
        return 0;
    }
    //encrypt plaintext
    not_used = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    if(not_used != 1){
        CryptoManager::manage_error("Encryption failed");
        return 0;
    }
    //increase the ciphertext length
    ciphertext_len += len;
    //move ahead pointer
    ciphertext += len;

    not_used = EVP_EncryptFinal(ctx, ciphertext , &len);
    if(not_used != 1) {
        manage_error("Finalizing encryption fail");
        return 0;
    }
    //increase the ciphertext length
    ciphertext_len += len;

    //getting the tag
    not_used = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag);
    if(not_used!= 1){
        CryptoManager::manage_error("getting authentication tag failed");
        return 0;
    }
    /* Clean up */
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
    if(!ctx) {
        CryptoManager::manage_error("allocation cipher context failed");
        return 0;
    }
    not_used = EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv);
    if(not_used != 1) {
        CryptoManager::manage_error("initializing cipher failed");
        return 0;
    }
    //Provide any AAD data.
    not_used = EVP_DecryptUpdate(ctx, nullptr, &len, aad, aad_len);
    if(not_used != 1) {
        CryptoManager::manage_error("setting aad failed");
        return 0;
    }
    //Provide the message to be decrypted, and obtain the plaintext output.
    not_used = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    if(not_used != 1) {
        CryptoManager::manage_error("decryption failed");
        return 0;
    }
    //update plaintext length
    plaintext_len = len;
    //move ahead the pointer
    plaintext += len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    not_used = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LEN, tag);
    if(not_used != 1) {
        CryptoManager::manage_error("setting expected tag value failed");
        return 0;
    }
    // finalize encryption and compare authentication tags
    not_used = EVP_DecryptFinal(ctx, plaintext, &len);

    // cleaning up
    EVP_CIPHER_CTX_cleanup(ctx);

    if(not_used > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}
//REMINDER: IV as AAD
void Managers::CryptoManager::manage_error(string message){
    std::cerr << message << std::endl;
}