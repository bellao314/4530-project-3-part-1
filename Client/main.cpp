#include "client.h"
#include <iostream>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <sys/socket.h>

// Default server IP address and port number if not specified
constexpr const char* DEFAULT_SERVER_IP = "127.0.0.1";
constexpr int DEFAULT_SERVER_PORT = 8080;

int main() {

    // Assign client socket descriptor to clientSocket when connecting to server with default ip address and port
    int clientSocket = connectToServer(DEFAULT_SERVER_IP, DEFAULT_SERVER_PORT);
    if (clientSocket == -1) {
        std::cout << "Error in connecting to socket" << std::endl;
        return 1;
    }
    std::cout << "Connected to server. Enter message 'quit' to exit: \n";

    while (true) {

        // Stores client input as message string
        std::string message;
        std::getline(std::cin, message);

        // Breaks the client application if message is 'quit'
        if (message == "quit") {
            break;
        }

        // Generate random IV and closes application if error
        unsigned char iv[EVP_MAX_IV_LENGTH];
        if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) != 1) {
            std::cerr << "Error: Failed to generate random IV." << std::endl;
            close(clientSocket);
            return 1;
        }

        // Encrypt message
        unsigned char ciphertext[BUFFER_SIZE];
        int ciphertext_len;
        encryptMessage(message, ciphertext, &ciphertext_len, iv);

        // Send IV and encrypted message to server
        send(clientSocket, iv, EVP_MAX_IV_LENGTH, 0);
        send(clientSocket, ciphertext, ciphertext_len, 0);
        std::cout << "Sent encrypted message to server." << std::endl;
    }
    close(clientSocket);
}
