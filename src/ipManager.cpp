#include <string>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <limits>
#include <sstream>
#include <bitset>

#include "ipManager.h"

int IpManager::setSubnet(std::string subnet) {
    this->subnet = subnet;
}

unsigned char* IpManager::getNextIp() {

    if (this->current_ip == NULL) {
        printf("current_ip is NULL\n");
        std::string delimiter = "/";
        std::string network_bits;
        std::string first_ip;
        int del_place;
        if((del_place = subnet.find(delimiter)) == std::string::npos) {
            network_bits = "32";
            first_ip = subnet;
        } else{
            printf("del_place: %d\n", del_place);
            network_bits = subnet.substr(del_place + 1);
            first_ip = subnet.substr(0, del_place);////
        } 

        std::cout << "first ip" << first_ip << std::endl;
        std::cout << "network bits " << network_bits << std::endl;

        this->current_ip = (unsigned char*)malloc(sizeof(unsigned char) * 4);
        memset(this->current_ip, 0, 4);

        unsigned int ip_int_tmp = ipToInt(first_ip);

        std::cout << "network bits" << std::stoi(network_bits) << std::endl;
        this->current_mask = (0xFFFFFFFF << (32 - std::stoi(network_bits))) & 0xFFFFFFFF;

        if(this->current_mask == 0xFFFFFFFF) {
            
            this->current_ip_int = ip_int_tmp;
            
        } else {
            ip_int_tmp &= this->current_mask;
            this->network_ip = ip_int_tmp;
    
            std::bitset<32> binary(this->current_mask);
            std::cout << "mask " << binary << std::endl;
    
            std::bitset<32> binary2(ip_int_tmp);
            std::cout << "ip " << binary2 << std::endl;
    
            this->current_ip_int = ip_int_tmp + 1;

        }
        
       
    } else {

        this->current_ip_int += 1;

        if ((this->network_ip & this->current_mask) != (this->current_ip_int & this->current_mask)) {
            std::cout << "ip out of range" << std::endl;
            return NULL;
        }

        if (this->current_ip_int == 0xFFFFFFFF) {
            std::cout << "ip out of range" << std::endl;
            return NULL;
        }

    }

    unsigned char* tmp = intToIp(this->current_ip_int);

    memcpy(this->current_ip, tmp, 4);

    free(tmp);

    return this->current_ip;
}

unsigned int IpManager::ipToInt(std::string ip) {
    unsigned int a, b, c, d;
    char ch;
    std::istringstream(ip) >> a >> ch >> b >> ch >> c >> ch >> d;
    return (a << 24) + (b << 16) + (c << 8) + d;
}

unsigned char* IpManager::intToIp(unsigned int ip_int) {

    unsigned char* result = (unsigned char*)malloc(sizeof(unsigned char) * 4);

    for(int i = 0; i < 4; i++) {
        result[i] = static_cast<unsigned char>((ip_int >> (24 - i * 8)) & 0xFF);
        printf("result[%d]: %d\n", i, result[i]);
    }

    printf("result: %d.%d.%d.%d\n", result[0], result[1], result[2], result[3]);

    return result; // seg fault here

}

unsigned char* IpManager::getCurrentIp() {
    return this->current_ip;
}