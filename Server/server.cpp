#include "server.h"
#include <openssl/rand.h>

// Handles client communication
void handleClient(int clientSocket) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error: Failed to create AES context." << std::endl;
        return;
    }

    EVP_CIPHER_CTX_init(ctx);

    unsigned char iv[EVP_MAX_IV_LENGTH];

    int bytesRead;
    while ((bytesRead = recv(clientSocket, iv, EVP_MAX_IV_LENGTH, 0)) > 0) {
        // Receive IV from client

        unsigned char encryptedBuffer[BUFFER_SIZE];
        bytesRead = recv(clientSocket, encryptedBuffer, BUFFER_SIZE, 0);

        unsigned char decryptedBuffer[BUFFER_SIZE];
        decryptMessage(ctx, encryptedBuffer, bytesRead, reinterpret_cast<const unsigned char*>(aes_key.c_str()), iv, decryptedBuffer);
        
        std::cout << "Received encrypted message: ";
        std::cout.write(reinterpret_cast<const char*>(encryptedBuffer), bytesRead);
        std::cout << std::endl;

        std::cout << "Decrypted message: " << decryptedBuffer << std::endl;

        // Re-encrypt the decrypted message before echoing it back to the client
        unsigned char echoIv[EVP_MAX_IV_LENGTH];
        if (RAND_bytes(echoIv, EVP_MAX_IV_LENGTH) != 1) {
            std::cerr << "Error: Failed to generate random IV." << std::endl;
            break;
        }

        unsigned char echoBuffer[BUFFER_SIZE];
        int echoLen;
        encryptMessage(reinterpret_cast<const char*>(decryptedBuffer), echoBuffer, &echoLen, echoIv);

        send(clientSocket, echoIv, EVP_MAX_IV_LENGTH, 0);
        send(clientSocket, echoBuffer, echoLen, 0);
    }

    EVP_CIPHER_CTX_free(ctx);
    close(clientSocket);
}
