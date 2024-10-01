#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pbc/pbc.h>
#include "MABE.hpp"
#include "nlohmann/json.hpp"
using json = nlohmann::json;

const int PORT = 8080; // Select a random port on startup


//maybe ad some json of all the clinets that exist and attributes they are allowed to have, tests to prove attributes
//external api to prove attributes, right now based off of trust
//confirm that other auths attributes can be used between authed clients





class SimpleClient {
private:
    int sockfd;
    struct sockaddr_in serverAddr;
    json publicInfo;
    json attributes;
    json receivedJson;
    json our_enc_msg;
    pairing_t pairing;
    char param[1024];
    json authStoreResponse = json::array();
    json clientKey;

public:
    SimpleClient(const std::string& serverIP) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd == -1) {
            std::cerr << "Failed to create socket" << std::endl;
            return;
        }

        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(PORT);
        inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr);
    }

    bool connect() {
        if (::connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
            std::cerr << "Failed to connect to server" << std::endl;
            return false;
        }
        std::cout << "Connected to server" << std::endl;

        //figure out how to deal with this, maybe split up transmisions or just throw it all into somehting huge
        //for now just throw it all into one big buffer
        char buffer[100000];

        ///getting public info
        ssize_t bytesReceived = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived == -1) {
            std::cerr << "Failed to receive public info from server" << std::endl;
            return false;
        }
        buffer[bytesReceived] = '\0';
        std::string publicInfoString(buffer);
        publicInfo = json::parse(publicInfoString);
        std::cout << "Received public info from server: " << std::endl;

        // getting auth info
        bytesReceived = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived == -1) {
            std::cerr << "Failed to receive auth stores from server" << std::endl;
            return false;
        }
        buffer[bytesReceived] = '\0';
        std::string authStoresString(buffer);
        authStoreResponse = json::parse(authStoresString); // Deserialize into json::array
        std::cout << "Received auth stores from server: "<< std::endl;


        // Automatically request attributes 2 and 4 upon connection
        // TODO: format ATTR 2,4 ATTR 1,1, meaning attribute 2 from auth 4, and attribute 1 from auth 1
        clientKey = askForKey();

        std::cout << "disconnecting from server" << std::endl;
        send(sockfd, nullptr, 0, 0);
        // Save the received attributes
        //saveAttributes(clientKey);

        return true;
    }

    json askForKey() {
        json attributesArray;


        //// test case ATTR 2,1,1 ATTR 2,1,3,2 ATTR 2,1,3
     
        std::string request;
        std::cout << "Enter the attribute request (e.g., 'ATTR 2,1,3,4,1' or 'ATTR 3,2,1 ATTR 1,2,3'): ";
        //TODO: eventually error check for 2 auths from each
        std::cout << "Please request at least 2 attributes from each auth." << std::endl;
        std::getline(std::cin, request);


        // Ensure the request is properly formatted before sending
        if (request.empty()) {
            std::cerr << "Request cannot be empty" << std::endl;
            return askForKey(); // or handle as needed
        }
  
        if (request.empty() || request.find("ATTR ") != 0) {
            std::cerr << "Request must start with 'ATTR '" << std::endl;
            return askForKey(); // Prompt again for a valid request
        }

        // Check for the presence of at least one space after the first "ATTR"
        size_t spacePos = request.find(' ', 5);
        if (spacePos == std::string::npos) {
            std::cerr << "Request format is invalid. Expected format: 'ATTR number,number '" << std::endl;
            return askForKey(); // Prompt again for a valid request
        }

        std::string response = sendMessage(request);
        if (response.empty()) {
            std::cerr << "No response received from server" << std::endl;
        } else {
            std::cout << "Server response: " << response << std::endl;
        }
        

        return attributesArray;
    }




    std::string sendMessage(const std::string& message) {
        if (send(sockfd, message.c_str(), message.length(), 0) == -1) {
            std::cerr << "Failed to send message" << std::endl;
            return "";
        }

        char buffer[50024];
        ssize_t bytesReceived = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived == -1) {
            std::cerr << "Failed to receive response" << std::endl;
            return "";
        }

        buffer[bytesReceived] = '\0';
        return std::string(buffer);
    }
    void prepEncryption() {
     

        //here we can change which attributes we use from which authorities
        //this is a2 and a1 from authority 1
        //IMPORTANT THIS IS HOW WE NEED TO PARSE OUT AUTH FILES FOR THE ATTRIBUTES THE CLIENT REQUESTS
        attributes["T_1_1"] = authStoreResponse[0]["T_a1"];
        attributes["T_1_2"] = authStoreResponse[0]["T_a2"];

        attributes["T_2_2"] = authStoreResponse[1]["T_a2"];
        attributes["T_2_1"] = authStoreResponse[1]["T_a1"];
        attributes["T_2_3"] = authStoreResponse[1]["T_a3"];

        attributes["T_3_1"] = authStoreResponse[2]["T_a1"];
        attributes["T_3_2"] = authStoreResponse[2]["T_a2"];
        

        size_t count = fread(param, 1, 1024, fopen("a.param","r"));
        if (!count) pbc_die("input error");
        pairing_init_set_buf(pairing,param, count);
    }

    void encryptMessage(std::string message) {


        element_t msg;
        element_init_GT(msg, pairing);
        // msg is where the symmetric key goes. Convert message string to void* for hashing
        element_from_hash(msg, (void*)message.c_str(), message.length());

        element_t Y, g2;
        element_init_GT(Y,pairing);
        element_init_G2(g2,pairing);

        convertFromString(Y, authStoreResponse[0]["Y_All"] );
        convertFromString(g2, publicInfo["g2"] );

        element_printf("%B\n", msg);
        our_enc_msg = encrypt(msg, attributes, Y, g2, pairing);
        std::string enc_string = our_enc_msg.dump();
        std::ofstream file("encrypt.json");
        file << our_enc_msg;        
    }

    void decryptMessage() {
        element_t msg, decrypted_msg;
        element_init_GT(msg, pairing); 
        element_init_GT(decrypted_msg, pairing);

        // For testing decryption, include the message or key here.
        element_from_hash(msg, (void*)"Hello", 5);

        element_t g1, g2, e_g1g2;
        element_init_G1(g1, pairing);
        element_init_G2(g2, pairing);
        element_init_GT(e_g1g2, pairing);

        convertFromString(g1, publicInfo["g1"]);
        convertFromString(g2, publicInfo["g2"]);
        convertFromString(e_g1g2, publicInfo["e_g1g2"]);

        json enc_msg;
        // Use receivedJson for decryption if available, otherwise read from the default file
        
        if (!receivedJson.empty()) {
            enc_msg = receivedJson;
            std::cout << "Using receivedJson for decryption." << std::endl;
        } else {
            std::ifstream encryptJson("encrypt.json", std::ios::in);
            if (!encryptJson) {
                std::cerr << "Failed to open encrypt.json" << std::endl;
                return;
            }
            enc_msg = json::parse(encryptJson);
            std::cout << "Using encrypt.json for decryption." << std::endl;
        }

        std::ifstream userInfoJson("userInfo.json", std::ios::in);
        json userInfo = json::parse(userInfoJson);
        element_printf("%B\n", msg);

        decrypt(enc_msg, userInfo, pairing, g1, g2, e_g1g2, msg, decrypted_msg);

    }


    //this bit is for when we want to wait for other clients to give us their encryption
    void waitForClients() {
        int serverSockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSockfd == -1) {
            std::cerr << "Failed to create server socket" << std::endl;
            return;
        }

        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(7070);

        if (bind(serverSockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
            std::cerr << "Failed to bind server socket on port 7070" << std::endl;
            return;
        }

        if (listen(serverSockfd, 1) == -1) {
            std::cerr << "Failed to listen on server socket" << std::endl;
            return;
        }

        std::cout << "Waiting for clients to connect on port 7070..." << std::endl;

    
        int clientSockfd = accept(serverSockfd, nullptr, nullptr);
        if (clientSockfd == -1) {
            std::cerr << "Failed to accept client connection" << std::endl;
            
        }

        std::cout << "Client connected!" << std::endl;

        // Receive JSON from the client
        char buffer[50024] = {0};
        int bytesRead = read(clientSockfd, buffer, sizeof(buffer) - 1);
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0'; // Null-terminate the received data
            std::string jsonString(buffer);
            receivedJson = json::parse(jsonString);
            std::cout << "receieved encrypted json" << std::endl;
        } else {
            std::cerr << "Failed to read from client socket" << std::endl;
        }

        close(clientSockfd); // Close the client socket after handling
    
    }
    void connectAndSend(const std::string& clientIP) {
        int clientSockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (clientSockfd == -1) {
            std::cerr << "Failed to create socket for client connection" << std::endl;
            return;
        }

        sockaddr_in clientAddr;
        clientAddr.sin_family = AF_INET;
        clientAddr.sin_port = htons(7070); // Connect to port 7070
        inet_pton(AF_INET, clientIP.c_str(), &clientAddr.sin_addr);

        if (::connect(clientSockfd, (struct sockaddr*)&clientAddr, sizeof(clientAddr)) == -1) {
            std::cerr << "Failed to connect to client at " << clientIP << std::endl;
            close(clientSockfd);
            return;
        }

        // Send the encrypted message JSON (our_enc_msg) to the connected client
        std::string message = our_enc_msg.dump();
        if (send(clientSockfd, message.c_str(), message.length(), 0) == -1) {
            std::cerr << "Failed to send message to client" << std::endl;
        } else {
            std::cout << "Sent encrypted message to client: " << clientIP << std::endl;
        }

        close(clientSockfd); // Close the socket after sending the message
    }



    void saveAttributes(const std::string& attributesJson) {
        json attributes = json::parse(attributesJson);
        std::ofstream outFile("received_attributes.json");
        outFile << attributes.dump(4);
        outFile.close();
    }

    ~SimpleClient() {
        close(sockfd);
    }
};

int main() {
    SimpleClient client("127.0.0.1");
  
        if (!client.connect()) {
            return 1;
        }
    
 
    client.prepEncryption();
    client.encryptMessage("Hello");

    char openPortChoice;
    std::cout << "Do you want to open a port to recieve encrypted data from other clients? (y/n): ";
    std::cin >> openPortChoice;

    if (openPortChoice == 'y' || openPortChoice == 'Y') {
        // Logic to open a port for other clients
        std::cout << "Opening port for other clients..." << std::endl;

        // Call the function to wait for clients
        client.waitForClients(); // Assuming waitForClients() is defined elsewhere in the class
    } else {
        std::cout << "Not opening a port for other clients." << std::endl;
    }

    char connectChoice;
    std::cout << "Do you want to connect and send encrypted data to other clients? (y/n): ";
    std::cin >> connectChoice;

    if (connectChoice == 'y' || connectChoice == 'Y') {
        // Placeholder for connecting to another client's port
        client.connectAndSend("127.0.0.1");

        // Logic to connect to the other client will go here
    } else {
        std::cout << "Not connecting to another client's port." << std::endl;
    }

    
    char decryptChoice;
    std::cout << "Do you want to decrypt a message? (y/n): ";
    std::cin >> decryptChoice;

    if (decryptChoice == 'y' || decryptChoice == 'Y') {
        // Call the decryption function or handle decryption logic here
        std::cout << "Decrypting message..." << std::endl;

        client.decryptMessage();
        // You may want to add the actual decryption logic here
    } else {
        std::cout << "Skipping decryption." << std::endl;
    }
    return 0;
}