#include <vector>
#include <unordered_map>
#include <algorithm>
#include <iostream>
#include "nlohmann/json.hpp"
#include "pbc.h"
#include "pbc_utils.h"  // for UNUSED_VAR
#include <fstream>
#include <iomanip>
#include <iostream>
#include "MABE.hpp"

using json = nlohmann::json;
//Compile with: g++ MABE-keyIssue.cpp -o MABE-keyIssue -lpbc -lgmp -I /usr/local/include/pbc

int main() {
    std::cout<<"Lets test the keyissuing.\n";
    std::ifstream jsonFile ( "public.json", std::ios::in );
    json publicInfo = json::parse( jsonFile );
    std::cout<<"Public loaded.\n";
    std::vector<json> authStores;
    for (int i = 1; i<=3; i++){
        std::ifstream authFile ( "Auth"+ std::to_string(i) +".json", std::ios::in );
        authStores.push_back(json::parse( authFile ));
        std::cout<<"Auth"<< i <<" loaded.\n";
    }
    pairing_t pairing;
    char param[1024];
    size_t count = fread(param, 1, 1024, fopen("a.param","r"));
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing,param, count);

    element_t g1;
    element_init_G1(g1, pairing);
    convertFromString(g1, publicInfo["g1"]);
    json userInfo = keyIssuing(authStores, pairing, g1);
    std::ofstream file("userInfo.json");
    file << userInfo;        
    std::cout<<" All done, look good hopefully.\n";
    return 0;
}    
   