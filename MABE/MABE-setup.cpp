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
//Compile with: g++ MABE-setup.cpp -o MABE-setup -lpbc -lgmp -I /usr/local/include/pbc

int main() {
    std::cout<<"Lets test the setup.\n";
    std::pair<std::vector<json>, json> files;        
    files =  setup(3, 4); // <number of authorites, number of attributes>
    std::ofstream file("public.json");
    file << files.second;

    for (int i = 0; i < files.first.size(); i++){
        std::ofstream file("Auth"+ std::to_string(i+1) +".json");
        file << files.first[i];
    }
    std::cout<<"All done, look good hopefully.\n";
    return 0;
}
  