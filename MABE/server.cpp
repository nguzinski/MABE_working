#include <iostream>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include "MABE.hpp"  // Include the header for cryptographic functions
#include "nlohmann/json.hpp"
#include <pbc/pbc.h>
#include <pbc/pbc_utils.h>  
using json = nlohmann::json;

const int PORT = 8080;
const int MAX_CLIENTS = 10;

class SimpleServer {
private:
    int serverSockfd;

    //REFACTOR'''

    struct sockaddr_in serverAddr;
    json authData;  // Store authentication data for this server
    json auth1Data; //this part has to be cleaned up so that auths can act individually
    json publicInfo;
    std::vector<json> authStores;
    char param[1024];
    //figure out if these have to be redone each pair or whatever

    pairing_t pairing;
    element_t g1, g2, e_g1g2;  // Cryptographic elements
    int attr;
    int auth;

public:
    SimpleServer() {
        serverSockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSockfd == -1) {
            std::cerr << "Failed to create server socket" << std::endl;
            return;
        }
        attr = 4;
        auth = 3;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(PORT);

        if (bind(serverSockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
            std::cerr << "Failed to bind server socket" << std::endl;
            return;
        }

        if (listen(serverSockfd, MAX_CLIENTS) == -1) {
            std::cerr << "Failed to listen on server socket" << std::endl;
            return;
        }

        std::cout << "Server started on port " << PORT << std::endl;
    
   
        mabeSetup();
        initPairingAndElements();

        

    }
    

    void mabeSetup() {

        // TODO: creat a.param here, initilize pbc_cm_t

        //this gets everything ready, public json and  auths 
        std::cout << "Lets test the setup.\n";
        std::pair<std::vector<json>, json> authfiles;

        // Assuming pbc_cm_t is properly defined and initialized elsewhere
        //set up creates a vector of auth jsons, and then the public.json in a pair
        authfiles = setup(auth, attr); // <number of authorities, number of attributes>
        std::ofstream file("public.json");
        std::cout << "public.json created";
        publicInfo = authfiles.second;  //this is the public.json
        file << authfiles.second;

        //print auth jsons
        //this will become redundant when we have the auths act independently
        for (int i = 0; i < authfiles.first.size(); i++) {
            std::ofstream file("Auth" + std::to_string(i + 1) + ".json");
            std::cout << "Auth" + std::to_string(i + 1) + ".json created";
            file << authfiles.first[i];
            authStores.push_back(authfiles.first[i]);
        }
  
    }

    void initPairingAndElements() {
    
        size_t count = fread(param, 1, 1024, fopen("a.param", "r"));
        if (!count) pbc_die("input error");
        pairing_init_set_buf(pairing, param, count);

        element_init_G1(g1, pairing);
        element_init_G2(g2, pairing);
        element_init_GT(e_g1g2, pairing);

        convertFromString(g1, publicInfo["g1"]);
        convertFromString(g2, publicInfo["g2"]);
        convertFromString(e_g1g2, publicInfo["e_g1g2"]);

        std::cout << "Pairing and elements initialized from JSON file." << std::endl;
    }


    json keyIssuance() {
        std::cout << "Issuing key.\n";


        json userInfo = keyIssuing(authStores, pairing, g1);
        std::ofstream userInfoFile("userInfo.json");
        if (!userInfoFile.is_open()) {
            std::cerr << "Failed to create userInfo.json" << std::endl;
            exit(EXIT_FAILURE); // Gracefully exit the program
        }
        userInfoFile << userInfo;
        return userInfo;
    }

    void handleClient(int clientSockfd) {
        char buffer[1024];
        ssize_t bytesReceived;

        while (true) {
            std::string publicInfoString = publicInfo.dump(); // Serialize publicInfo to a string
            if (send(clientSockfd, publicInfoString.c_str(), publicInfoString.length(), 0) == -1) {
                std::cerr << "Failed to send public info to client" << std::endl;
                return;
            }
            std::cout << "Sent public info to client: " << std::endl;


            //this will become redundant when we have the auths act independently
            json authStoreResponse = json::array();
            for (const auto& authStore : authStores) {
                authStoreResponse.push_back(authStore);
            }
            std::string authStoreString = authStoreResponse.dump(); // Serialize authStores to a string
            if (send(clientSockfd, authStoreString.c_str(), authStoreString.length(), 0) == -1) {
                std::cerr << "Failed to send auth stores to client" << std::endl;
                return;
            }
            std::cout << "Sent auth stores to client" << std::endl;
            

            bytesReceived = recv(clientSockfd, buffer, sizeof(buffer), 0);

            if (bytesReceived == -1) {
                std::cerr << "Client disconnected" << std::endl;
                return;
            }


            buffer[bytesReceived] = '\0';
            std::string request(buffer);

            std::cout << "Received: " << request << std::endl;

            // this figures out which attributes the client wants

        
            std::string response = processAttributeRequest(request);
            // Save the output to a variable or file as needed
            std::ofstream responseFile("attributeResponse.json");
            if (!responseFile.is_open()) {
                std::cerr << "Failed to create attributeResponse.json" << std::endl;
                return;
            }
            responseFile << response;
            responseFile.close();

            if (send(clientSockfd, response.c_str(), response.length(), 0) == -1) {
                std::cerr << "Failed to send response to client" << std::endl;
                return;
            }
            
        }
    }

    //TODO: clean up, figure out what attributes the client wants, and pass that info onto the key issuance

    //////////// MAKE THIS PARSER WORK AND YOU ARE BASICALLY DONE
    std::string processAttributeRequest(const std::string& request) {
        std::istringstream requestStream(request);
        std::string token;
        std::vector<std::vector<int>> attributesVector;

        while (requestStream >> token) {
            if (token == "ATTR") {
                std::vector<int> currentAttributes;
                std::string numbers;
                requestStream >> numbers; // Read the numbers after "ATTR"
                std::istringstream numStream(numbers);
                std::string number;

                // Split the numbers by commas
                while (std::getline(numStream, number, ',')) {
                    currentAttributes.push_back(std::stoi(number)); // Convert to int and add to vector
                }
                attributesVector.push_back(currentAttributes); // Add the vector to attributesVector
            }
        }
        std::cout << "Attributes Vector: " << std::endl;
        for (const auto& attributes : attributesVector) {
            std::cout << "[ ";
            for (const auto& attr : attributes) {
                std::cout << attr << " ";
            }
            std::cout << "]" << std::endl;
        }

        //first int is attr, second is auth
        
        std::vector<json> whatClientWants;
        
        for (const auto& attributeSet : attributesVector) {
            // The last element is the authority
            int authority = attributeSet.back();
            // The rest are the attributes
            std::vector<int> attributeList(attributeSet.begin(), attributeSet.end() - 1);

            for (const auto& attribute : attributeList) {
                std::cout << "Processing authStore for attribute: " << attribute << " and authority: " << authority << std::endl;
                json temp;

                // Find the corresponding auth store based on authority
                const auto& auth = authStores[authority - 1]; // Assuming authority is 1-indexed

                temp["ID"] = auth["ID"];
                temp["y"] = auth["y"];
                temp["Y"] = auth["Y"];
                temp["v"] = auth["v"];
                temp["x"] = auth["x"];
                //temp["Y_All"] = auth["Y_All"];

                for (const auto& [key, value] : auth.items()) {
                    if (key.rfind("s_", 0) == 0) { // Check if key starts with "s_"
                        temp[key] = value;
                    }
                }

                temp["attr_num"] = attributeList.size(); 
                temp["t_a" + std::to_string(attribute)] = auth["t_a" + std::to_string(attribute)];

                whatClientWants.push_back(temp);
            }
        }

        
        
       
        element_t g1;
        element_init_G1(g1, pairing);
        convertFromString(g1, publicInfo["g1"]);
        json userInfo = keyIssuing(whatClientWants, pairing, g1);
        std::ofstream file("userInfo.json");
        file << userInfo;        
        std::cout<<" All done, look good hopefully.\n";
     



        json result = json::object();
    
        std::cout<<result.dump(4);
        return result.dump();  // Serialize the JSON object to a string
    }


    //TODO: test multiple clients
    void start() {
        while (true) {
            struct sockaddr_in clientAddr;
            socklen_t clientAddrLen = sizeof(clientAddr);

            std::cout << "Waiting for a client to connect..." << std::endl;
            int clientSockfd = accept(serverSockfd, (struct sockaddr*)&clientAddr, &clientAddrLen);

            if (clientSockfd == -1) {
                std::cerr << "Failed to accept client connection" << std::endl;
                continue;
            }

            std::cout << "New client connected" << std::endl;
            //this is where it threads, check to see if start, will keep running while this is running
            std::thread clientThread(&SimpleServer::handleClient, this, clientSockfd);
            clientThread.detach();
        }
    }

    ~SimpleServer() {
        close(serverSockfd);
    }
};

int main() {
    SimpleServer server;
    server.start();
    return 0;
}