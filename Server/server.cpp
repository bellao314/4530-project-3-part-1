#include "server.h"

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

        // Echo back the decrypted message to the client
        send(clientSocket, decryptedBuffer,  strlen(reinterpret_cast<const char*>(decryptedBuffer)), 0);
    }

    EVP_CIPHER_CTX_free(ctx);
    close(clientSocket);
}
