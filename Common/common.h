#ifndef COMMON_H
#define COMMON_H

#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/evp.h>
#include <string>

constexpr int BUFFER_SIZE = 1024;
constexpr int PORT = 8080;
extern std::string aes_key;

void handleErrors();
void encryptMessage(const std::string& plaintext, unsigned char* ciphertext, int* ciphertext_len, unsigned char* iv);
void decryptMessage(EVP_CIPHER_CTX* ctx, const unsigned char* encryptedData, int encryptedLen, const unsigned char* aesKey, const unsigned char* iv, unsigned char* decryptedBuffer);

#endif // COMMON_H