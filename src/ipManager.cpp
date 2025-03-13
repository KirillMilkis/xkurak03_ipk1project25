#include <string>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream> 
#include <sstream>
#include <bitset>

#include "ipManager.h"

// int setSubnet(std::string subnet) {
//     subnet = subnet;
// }

char* IpManager::getNextIp() {
    std::string delimiter = "/";
    std::string  range = subnet.substr(subnet.find(delimiter) + 1);
    std::string first_ip = subnet.substr(0, subnet.find(delimiter));

    current_ip = first_ip;
    current_subnet = std::stoi(range);

    unsigned int ip_int = ipToInt(current_ip);
    unsigned int mask = (0xFFFFFFFF << (32 - current_subnet)) & 0xFFFFFFFF;  

    ip_int &= mask;
    ip_int += 1;

    char next_ip = intToIp(ip_int);

    std::cout << next_ip << "next ip" << "\n";
}

unsigned int IpManager::ipToInt(std::string ip) {
    unsigned int a, b, c, d;
    char ch;
    std::istringstream(ip) >> a >> ch >> b >> ch >> c >> ch >> d;
    return (a << 24) + (b << 16) + (c << 8) + d;
}

char* IpManager::intToIp(unsigned int ip) {
    char result[4];

    for(int i = 0; i < 4; i++) {
        result[i] = (ip >> (i * 8)) & 0xFF;
    }

    return result;
}