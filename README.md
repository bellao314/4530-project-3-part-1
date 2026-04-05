Be sure to have OpenSSL library installed. If you run this project on Hopper, you don't need to install anything.
You only need to write code in the common.cpp file under the Common folder (encryptMessage and decryptMessage methods)

To run the chat application:
1. In the project3_part1 directory, run the following commands:
   + mkdir build
   + cd build
   + cmake ..
   + make
2. Run the client and server (you can have multiple client instances):
+ In the build directory, run the server by: (run the server first)
  + cd Server
  + ./server_executable
+ Open another terminal, in the build directory, run the client by:
  + cd Client
  + ./client_executable
   
Testing:
In the client terminal, type a message
In the server terminal, an encrypted message and the message you just typed in the client terminal will show up
If both messages match, then you do encryption and decryption methods correctly


