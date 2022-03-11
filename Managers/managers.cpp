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
#include <openssl/rand.h>
#include <iostream>
#include <string>
#include <limits>

#define CIPHER  EVP_aes_128_gcm()
#define DIGEST EVP_sha256()
#define TAG_LEN 16
#define OPENSSL_FAIL(result,message,error_value) \
       if(!result){               \
            CryptoManager::manage_error(message);                         \
            return error_value;                                  \
       }
#define IF_IO_ERROR(result,error_value) \
        if(result <= 0) \
            return error_value;
using namespace std;
int Managers::SocketManager::write_n(int socket, size_t amount, void *buff) {
    size_t left = amount;
    size_t n;
    char* buff_ptr = (char*) buff;
    while (left > 0){
        n = write(socket,buff_ptr,amount);
        if(n == -1){
            if (errno == EINTR ) continue;
            else if( errno == EPIPE) return 0; //ignore
            return -1;
        }
        left -= n;
        buff_ptr += n;

    }
    return 1;
}
int Managers::SocketManager::read_n(int socket, size_t amount, void *buff) {
    size_t left = amount;
    size_t n;
    char* buff_ptr = (char*) buff;
    while (left > 0){
        n = read(socket,buff_ptr,amount);
        if(n == -1) {
            if (errno == EINTR) continue;
            else if (errno == ECONNRESET) return 0; //ignore
            return -1;
        }
        left -= n;
        buff_ptr += n;
    }
    return 1;
}

int Managers::SocketManager::write_string(int socket, std::string str) {
    size_t size = str.length();
    int result;
    result = SocketManager::write_n(socket,sizeof(size_t),(void*) &size);
    if( result <= 0)
        return result;
    result =  SocketManager::write_n(socket,size,(void*) str.c_str());
    return result;
}

int Managers::SocketManager::read_string(int socket, std::string &str) {
    size_t size;
    int result;
    result = SocketManager::read_n(socket,sizeof(size_t),(void*) &size);
    if(result <= 0)
        return result;
    char* data = new char[size+1];
    result = SocketManager::read_n(socket,size,(void*) data);
    if(result){
        data[size] = '\0';
        str.append(data);
    }
    free(data);
    return result;

}
int Managers::SocketManager::send_message(int socket, Message *msg) {
    BIO* m_bio = BIO_new(BIO_s_mem());
    int result;
    uint32_t nonce;
    int tmp;
    OPENSSL_FAIL(m_bio,"allocating bio fail",0)

    switch (msg->getType()) {
        case AUTH_REQUEST:
            tmp = msg->getType();
            result = SocketManager::write_n(socket,sizeof(int),(void*)&tmp);
            IF_IO_ERROR(result,result)
            result = SocketManager::write_string(socket,msg->getSender());
            IF_IO_ERROR(result,result)
            nonce = msg->getPayload()->getNonce();
            //cout << nonce << endl;
            result = SocketManager::write_n(socket,sizeof(uint32_t),(void*)&nonce);
            break;
        case AUTH_RESPONSE:
            break;
        case AUTH_KEY_EXCHANGE:
            break;
        case AUTH_KEY_EXCHANGE_RESPONSE:
            break;
        default:
            break;
    }
    BIO_free(m_bio);
    return result;
}
Message* Managers::SocketManager::read_message(int socket){
    //BIO* m_bio = BIO_new(BIO_s_mem());
    int result;
    Message* msg = nullptr;
    int tmp;
    uint32_t nonce;
    //char username[MAX_USERNAME];
    string username;
    OPENSSL_FAIL(m_bio,"allocating bio fail",0)
    int type = 0;
    size_t size;
    result = SocketManager::read_n(socket,sizeof(int),(void*)&type);
    IF_IO_ERROR(result, nullptr)
    switch (type) {
        case AUTH_REQUEST:
            //read username
            result = SocketManager::read_string(socket,username);
            IF_IO_ERROR(result, nullptr)
            //cout << username << endl;
            //read nonce
            result = SocketManager::read_n(socket,sizeof(uint32_t),(void*)&nonce);
            //cout << nonce << endl;
            if(result){
                msg = new Message();
                ISNOT(msg,"allocating message failed")
                msg->setSender(username);
                msg->getPayload()->setNonce(nonce);
            }
            break;
        case AUTH_RESPONSE:
            break;
        case AUTH_KEY_EXCHANGE:
            break;
        case AUTH_KEY_EXCHANGE_RESPONSE:
            break;
        default:
            break;
    }
    //BIO_free(m_bio);
    return msg;
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
    //create context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    OPENSSL_FAIL(ctx,"allocation cipher context failed",0)
    //init context
    not_used = EVP_EncryptInit(ctx,CIPHER,key,iv);
    OPENSSL_FAIL(not_used,"initializing cipher failed",0)
    //Provide any AAD data. This can be called zero or more times as required
    not_used = EVP_EncryptUpdate(ctx, nullptr, &len, aad, aad_len);
    OPENSSL_FAIL(not_used,"adding aad failed",0);
    //encrypt plaintext
    not_used = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    OPENSSL_FAIL(not_used,"encryption failed",0)
    //increase the ciphertext length
    ciphertext_len += len;
    //move ahead pointer
    ciphertext += len;
    //finalize encryption
    not_used = EVP_EncryptFinal(ctx, ciphertext , &len);
    OPENSSL_FAIL(not_used,"finalizing encryption fail",0)
    //increase the ciphertext length
    ciphertext_len += len;

    //getting the tag
    not_used = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag);
    OPENSSL_FAIL(not_used,"getting authentication tag failed",0)
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
    OPENSSL_FAIL(ctx,"allocation cipher context failed",0)
    not_used = EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv);
    OPENSSL_FAIL(not_used,"initializing cipher failed",0)
    //Provide any AAD data.
    not_used = EVP_DecryptUpdate(ctx, nullptr, &len, aad, aad_len);
    OPENSSL_FAIL(not_used,"adding aad failed",0);
    //Provide the message to be decrypted, and obtain the plaintext output.
    not_used = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    OPENSSL_FAIL(not_used,"decryption failed",0)
    //update plaintext length
    plaintext_len = len;
    //move ahead the pointer
    plaintext += len;

    //Set expected tag value. Works in OpenSSL 1.0.1d and later
    not_used = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LEN, tag);
    OPENSSL_FAIL(not_used,"setting expected tag value failed",0)

    // finalize decryption and compare authentication tags
    not_used = EVP_DecryptFinal(ctx, plaintext, &len);

    // cleaning up
    EVP_CIPHER_CTX_cleanup(ctx);

    if(not_used > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return 0;
    }
}
//REMINDER: IV as AAD
void Managers::CryptoManager::manage_error(string message){
    std::cerr << message << std::endl;
    ERR_print_errors_fp(stderr);
}
//return
unsigned char* Managers::CryptoManager::sign(unsigned char *plaintext, uint64_t plain_size, EVP_PKEY *sign_key, uint32_t* sgnt_size) {
    int not_used;
    unsigned char * sgnt_buff; //signature
    //creating signature context
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    OPENSSL_FAIL(md_ctx,"allocating signature context failed", nullptr)

    not_used = EVP_SignInit(md_ctx,DIGEST);
    OPENSSL_FAIL(not_used,"initializing signature context failed", nullptr)
    not_used = EVP_SignUpdate(md_ctx, plaintext, plain_size);
    OPENSSL_FAIL(not_used,"computing signature failed", nullptr)
    sgnt_buff = new unsigned char [EVP_PKEY_size(sign_key)];
    ISNOT(sgnt_buff,"allocating signature buffer failed")
    //finalize signature
    not_used = EVP_SignFinal(md_ctx, sgnt_buff, sgnt_size, sign_key);
    OPENSSL_FAIL(not_used,"finalizing signature failed", nullptr)


    // delete the digest and the private key from memory:
    EVP_MD_CTX_free(md_ctx);
    //EVP_PKEY_free(prvkey);
    return  sgnt_buff;
}

int Managers::CryptoManager::verify_signature(unsigned  char*signature, uint32_t  signature_size, unsigned  char* plain_text,
                                              uint64_t  plain_size, EVP_PKEY* pub_key){
    int not_used;
    int result;
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    OPENSSL_FAIL(md_ctx,"allocating signature context failed", 0)
    not_used = EVP_VerifyInit(md_ctx,DIGEST);
    OPENSSL_FAIL(not_used,"initializing signature context failed", 0)
    not_used =  EVP_VerifyUpdate(md_ctx, plain_text, plain_size);
    OPENSSL_FAIL(not_used,"very update failed", 0)
    result = EVP_VerifyFinal(md_ctx,signature,signature_size,pub_key);
    EVP_MD_CTX_free(md_ctx);
    return result == 1 ? result : 0;
}

X509* Managers::CryptoManager::open_certificate(string path){
    FILE* file;
    file = fopen(path.c_str(),"r");
    if(!file) {
        cerr << "error opening " << path << endl;
        return nullptr;
    }
    X509* cert;
    cert = PEM_read_X509(file,NULL,NULL,NULL);
    OPENSSL_FAIL(cert,"Reading cert " + path + " failed", nullptr)
    fclose(file);
    return cert;
}
X509_CRL* Managers::CryptoManager::open_crl(string path){
    FILE* file;
    file = fopen(path.c_str(),"r");
    if(!file) {
        cerr << "error opening " << path << endl;
        return nullptr;
    }
    X509_CRL* crl;
    crl = PEM_read_X509_CRL(file,NULL,NULL,NULL);
    OPENSSL_FAIL(crl,"Reading CRL " + path + " failed", nullptr)
    fclose(file);
    return crl;

}
int Managers::CryptoManager::verify_cert(X509* ca_cert, X509_CRL* crl, X509* cert) {
    X509_STORE* store;
    int not_used;
    store = X509_STORE_new();
    OPENSSL_FAIL(not_used,"allocating store failed",0)
    //add CA's cert
    not_used = X509_STORE_add_cert(store,ca_cert);
    OPENSSL_FAIL(not_used,"adding certificate failed",0)
    //add crl list
    not_used = X509_STORE_add_crl(store,crl);
    OPENSSL_FAIL(not_used,"adding crl failed",0);
    //to use crl
    not_used = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    OPENSSL_FAIL(not_used,"setting clr flag fail",0)

    //certificate verification
    X509_STORE_CTX* ctx_store = X509_STORE_CTX_new();
    OPENSSL_FAIL(ctx_store,"allocating store context failed",0)
    //init store context
    not_used = X509_STORE_CTX_init(ctx_store,store,cert,NULL);
    OPENSSL_FAIL(not_used,"initializing ctx_store failed",0)
    //verify cert
    int result = X509_verify_cert(ctx_store);
    //clean up
    X509_STORE_free(store);
    X509_STORE_CTX_free(ctx_store);

    return result == 1 ? result : 0;
}

int Managers::CryptoManager::generate_random_bytes(unsigned char* bytes,int amount) {
    static uint32_t times = 0;
    int not_used;
    //reseed
    if(times >= numeric_limits<uint32_t>::max() - 1 ) {
        not_used = RAND_poll();
        OPENSSL_FAIL(not_used,"polling error",0);
        times = 0;
    }
    not_used = RAND_bytes(bytes,amount);
    if(not_used == -1){
        cerr << "RAND_bytes() is not supported" << endl;
        return 0;
    }
    OPENSSL_FAIL(not_used,"generating rand bytes failed",0)
    return 1;
}

int Managers::CryptoManager::generate_nonce(uint32_t *nonce) {
    int result;
    unsigned char* bytes = new unsigned char[4];
    result = CryptoManager::generate_random_bytes(bytes,4);
    if(result)
        *nonce = (uint32_t )((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]);
    free(bytes);
    return result;
}