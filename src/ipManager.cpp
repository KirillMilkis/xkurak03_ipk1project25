#include <string>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream> 
#include <sstream>
#include <bitset>

#include "ipManager.h"

int IpManager::setSubnet(std::string subnet) {
    subnet = subnet;
}

char* IpManager::getNextIp() {
    if (current_ip.empty()) {
        std::string delimiter = "/";
        std::string network_bits = subnet.substr(subnet.find(delimiter) + 1);
        std::string first_ip = subnet.substr(0, subnet.find(delimiter));

        unsigned int ip_int = ipToInt(first_ip);

        unsigned int current_mask = (0xFFFFFFFF << (32 - std::stoi(network_bits))) & 0xFFFFFFFF;
        
        ip_int &= mask;
        network_ip = ip_int;

        std::bitset<32> binary(current_mask);
        std::cout << "mask " << binary << std::endl;

        current_ip_int = ip_int + 1;
    } else {

        current_ip_int += 1;

        if ((network_ip & current_mask) != (current_ip_int & current_mask)) {
            std::cout << "ip out of range" << std::endl;
            return NULL;
        }

        if (current_ip_int == 0xFFFFFFFF) {
            std::cout << "ip out of range" << std::endl;
            return NULL;
        }

    }

    std::string next_ip = intToIp(current_ip_int);

    current_ip = next_ip;

    return strdup(next_ip.c_str());
}

unsigned int IpManager::ipToInt(std::string ip) {
    unsigned int a, b, c, d;
    char ch;
    std::istringstream(ip) >> a >> ch >> b >> ch >> c >> ch >> d;
    return (a << 24) + (b << 16) + (c << 8) + d;
}

std::string IpManager::intToIp(unsigned int ip) {
    std::string result;

    for(int i = 0; i < 4; i++) {
        result += std::to_string((ip >> (24 - i * 8)) & 0xFF);
        if(i < 3) {
            result += ".";
        }  
    }

    return result;
}