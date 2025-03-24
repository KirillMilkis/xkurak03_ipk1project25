#include <string>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <limits>
#include <cstdint>
#include <sstream>
#include <bitset>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <algorithm>  

#include "ipManager.h"

bool IpManager::useNextSubnet() {
    
    this->subnet_num += 1;

    if(this->subnet_num < this->ipv4_subnets.size()) {
        this->current_subnet = this->ipv4_subnets[this->subnet_num];
    } else if((this->subnet_num - this->ipv4_subnets.size()) < this->ipv6_subnets.size()) {
        this->is_ipv6 = true;
        this->current_subnet = this->ipv6_subnets[this->subnet_num - this->ipv4_subnets.size()];
    } else {
        return false;
    }
    
    if(!this->current_subnet.empty()) { //
        return true;
    }

}


int IpManager::printSubnetList(std::vector<std::string> subnets_to_print, int ip_len) {
    
    int del_place;
    int ip_count;

    for(std::string subnet : subnets_to_print){
        std::cout << "Scanning subnet: " << subnet << std::endl;
        del_place = subnet.find("/");
        ip_count = (del_place == std::string::npos) ? 1 
                      : ((1 << (ip_len - std::stoi(subnet.substr(del_place + 1)))) - 2);
        std::cout << subnet << " " << ip_count << std::endl;
    }

    return 0;
}

#define IPV4_LEN 32
#define IPV6_LEN 128

int IpManager::printAllSubnets(){

    std::cout << "Scanning ranges: " << std::endl;

    this->printSubnetList(this->ipv4_subnets, IPV4_LEN);
    
    this->printSubnetList(this->ipv6_subnets, IPV6_LEN);

    return 0;

}

#define DEFAULT_SUBNET_MASK "32"

template <typename T, size_t N>
bool IpManager::calculateIp(std::array<T, N>& current_ip, std::array<T, N>& network_ip, std::array<T, N>& current_mask, int ip_size) {
    if(this->is_first_ip){
        int del_place = this->current_subnet.find("/"); //
        std::string subnet_mask = (del_place == std::string::npos) ? std::to_string(ip_size) : this->current_subnet.substr(del_place + 1);
        std::string subnet_addr = (del_place == std::string::npos) ? this->current_subnet : this->current_subnet.substr(0, del_place);
        
        std::cout << "Subnet mask: " << subnet_mask << std::endl;
        std::cout << "Subnet addr: " << subnet_addr << std::endl;
        int maskBits = std::stoi(subnet_mask);
        for (int i = 0; i < N; i++) {
            if (maskBits >= 8) {
                current_mask[i] = 0xFF;  
                maskBits -= 8;
            } else if (maskBits > 0) {
                current_mask[i] = (0xFF << (8 - maskBits)) & 0xFF;
                break;
            } else {
                current_mask[i] = 0;
            }
        }

        current_ip = this->stringToBytes<N>(subnet_addr);
        network_ip = this->biteAND(current_ip, current_mask);
        current_ip = network_ip;

        if(!std::all_of(current_mask.begin(), current_mask.end(), [](unsigned char c){ return c == 0xFF; })) {

            this->incrementIP(current_ip);

        }

        this->is_first_ip = false;


    } else {
        
        this->incrementIP(current_ip);

        if(this->biteAND(network_ip, current_mask) != this->biteAND(current_ip, current_mask)) {
            return false;
        }

        if(this->isOver()) return false;
    }

    return true;
}



unsigned char* IpManager::getNextIp() {

    if(!this->is_ipv6){
        if (!calculateIp(this->current_ipv4, this->network_ipv4, this->current_mask_ipv4, 32)){
            return nullptr;
        }      

    } else {
        if(!calculateIp(this->current_ipv6, this->network_ipv6, this->current_mask_ipv6, 128)){
            return nullptr;
        }
    }

    
    if (this->is_ipv6) {
        this->current_ip_char = bytesToChar<unsigned char, 16>(this->current_ipv6, 16);
    } else {
        this->current_ip_char = bytesToChar<unsigned char, 4>(this->current_ipv4, 4);
    }

    return this->current_ip_char.data();
}

bool IpManager::isOver() {
    int fullOctets = 0;
    
    if(this->is_ipv6) {
        for (auto& octet : this->current_ipv6) {
            if (octet == 0xFF) {
                fullOctets++;
            }
        }
        return fullOctets == 16;
    } else {
        for (auto& octet : this->current_ipv4) {
            if (octet == 0xFF) {
                fullOctets++;
            }
        }
        return fullOctets == 4;
    }
   
    return this->is_ipv6 ? fullOctets == 16 : fullOctets == 4;
}

template <typename T, size_t N>
std::array<unsigned char, N> IpManager::biteAND(const std::array<T, N>& vector1, const std::array<T, N>& vector2) {
    std::array<unsigned char, N> result;
    for (size_t i = 0; i < N; i++) {
        result[i] = vector1[i] & vector2[i];
    }
    return result;
}


template <typename T, size_t N>
void IpManager::incrementIP(std::array<T, N>& ip) {
    for (int i = N - 1; i >= 0; --i) {
        if (++ip[i] != 0) break;
    }
}

template <size_t N>
std::array<unsigned char, N> IpManager::stringToBytes(const std::string& ip) {

    std::array<unsigned char, N> result;

    if (this->is_ipv6) {
        inet_pton(AF_INET6, ip.c_str(), result.data());  
    } else {
        inet_pton(AF_INET, ip.c_str(), result.data());   
    }

    for(int i = 0; i < N; i++) {
        std::cout << (int)result[i] << std::endl;
    }

    return result;
}

template <typename T, size_t N>
std::string IpManager::bytesToString(std::array<T, N> ip) {
    char buffer[INET6_ADDRSTRLEN];
    if(this->is_ipv6) {
        inet_ntop(AF_INET6, ip.data(), buffer, sizeof(buffer));
    } else {
        inet_ntop(AF_INET, ip.data(), buffer, sizeof(buffer));
    }
    return std::string(buffer);
}

template <typename T, size_t N>
std::vector<unsigned char> IpManager::bytesToChar(std::array<T, N> ip, size_t size) {
    char temp_buffer[INET6_ADDRSTRLEN];
    if (inet_ntop(this->is_ipv6 ? AF_INET6 : AF_INET, ip.data(), temp_buffer, sizeof(temp_buffer)) == nullptr) {
        exit(1);
    }

   
    std::vector<unsigned char> buffer(temp_buffer, temp_buffer + size);
    return buffer;
}


unsigned int IpManager::stringToInt(std::string ip) {
    unsigned int a, b, c, d;
    char ch;
    std::istringstream(ip) >> a >> ch >> b >> ch >> c >> ch >> d;
    a &= 0xFF;
    b &= 0xFF;
    c &= 0xFF;
    d &= 0xFF;
    return (a << 24) + (b << 16) + (c << 8) + d;
}




unsigned char* IpManager::intToChar(unsigned int ip_int) {

    unsigned char* result = (unsigned char*)malloc(sizeof(unsigned char) * 4);

    for(int i = 0; i < 4; i++) {
        result[i] = static_cast<unsigned char>((ip_int >> (24 - i * 8)) & 0xFF);
        // printf("result[%d]: %d\n", i, result[i]);
    }

    return result; 

}

std::string IpManager::intToString(unsigned int ip_int) {
    std::string result = std::to_string((ip_int >> 24) & 0xFF) + "." + std::to_string((ip_int >> 16) & 0xFF) + "." + std::to_string((ip_int >> 8) & 0xFF) + "." + std::to_string(ip_int & 0xFF);
    return result;
}

unsigned char* IpManager::getCurrentIp() {
    return this->is_ipv6 ? this->current_ipv6.data() : this->current_ipv4.data();
}

std::string IpManager::getCurrentIpString() {
    std::array<unsigned char, 16> ip_array_v6;
    std::array<unsigned char, 4> ip_array_v4;

    if (this->is_ipv6) {
        std::copy(this->current_ipv6.begin(), this->current_ipv6.end(), ip_array_v6.begin());
        return this->bytesToString(ip_array_v6);
    } else {
        std::copy(this->current_ipv4.begin(), this->current_ipv4.end(), ip_array_v4.begin());
        return this->bytesToString(ip_array_v4);
    }
}

bool IpManager::isIPv6(const std::string& ip) {
    return ip.find(":") != std::string::npos;
}