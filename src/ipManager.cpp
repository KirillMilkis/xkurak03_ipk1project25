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
#include <cmath>

#include "ipManager.h"

bool IpManager::useNextSubnet() {
    
    this->subnet_num += 1;

    if(this->subnet_num < (int)this->ipv4_subnets.size()) {
        this->current_subnet = this->ipv4_subnets[this->subnet_num];
        this->is_first_ip = true;
    } else if((this->subnet_num - this->ipv4_subnets.size()) < this->ipv6_subnets.size()) {
        this->is_ipv6 = true;
        this->current_subnet = this->ipv6_subnets[this->subnet_num - this->ipv4_subnets.size()];
        this->is_first_ip = true;
    } else {
        return false;
    }
    
    if(!this->current_subnet.empty()) { 
        return true;
    }

    return false;

}

bool IpManager::checkSubnet(std::string subnet_mask, std::string subnet_addr) {

    if(!this->isValidSubnetMask(subnet_mask)) {
        std::cerr << "Invalid subnet mask" << std::endl;
        return false;
    }

    if(!(this->is_ipv6 ? this->isValidIPv6(subnet_addr) : this->isValidIPv4(subnet_addr))) {
        std::cerr << "Invalid IP address" << std::endl;
        return false;
    }
    


    return true;
}

bool IpManager::printSubnetList(std::vector<std::string> subnets_to_print, int ip_len) { //
    
    int del_place;
    int ip_count;

    for(std::string subnet : subnets_to_print){
        del_place = subnet.find("/");

        std::string subnet_mask = (del_place ==  static_cast<int>(std::string::npos)) ? std::to_string(this->is_ipv6 ? 128 : 32) : this->current_subnet.substr(del_place + 1);
        std::string subnet_addr = (del_place ==  static_cast<int>(std::string::npos)) ? this->current_subnet : this->current_subnet.substr(0, del_place);

        std::cout << subnet_addr << " " << subnet_mask << std::endl; //
        if(!this->checkSubnet(subnet_mask, subnet_addr)) return false; 
        
        ip_count = (std::stoi(subnet_mask) == 32 || std::stoi(subnet_mask) == 128) ? 1 
                      : (static_cast<int>(std::pow(2, ip_len - std::stoi(subnet_mask))) - 2);
        std::cout << subnet_addr << " " << ip_count << std::endl;
    }

    return true;
}

#define IPV4_LEN 32
#define IPV6_LEN 128

void IpManager::printAllSubnets(){

    std::cout << "Scanning ranges: " << std::endl;

    if(!this->printSubnetList(this->ipv4_subnets, IPV4_LEN)) exit(EXIT_FAILURE);
    
    if(!this->printSubnetList(this->ipv6_subnets, IPV6_LEN)) exit(EXIT_FAILURE);

}

bool IpManager::isValidSubnetMask(const std::string& subnet_mask) {
    std::regex mask_regex(R"(^\d{1,3}$)"); // Number from 0 to 128
    if (!std::regex_match(subnet_mask, mask_regex)) {
        return false;
    }

    int mask = std::stoi(subnet_mask);

    if(this->is_ipv6) {
        return mask >= 0 && mask <= 128;
    } else {
        return mask >= 0 && mask <= 32;
    }
}

bool IpManager::isValidIPv4(const std::string& ip) {
    std::regex ipv4_regex(R"(^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$)");
    std::smatch match;
    if (!std::regex_match(ip, match, ipv4_regex)) {
        return false;
    }
    for (int i = 1; i <= 4; ++i) {
        int num = std::stoi(match[i].str());
        if (num < 0 || num > 255) return false;
    }
    return true;
}

bool IpManager::isValidIPv6(const std::string& ip) {
    std::regex ipv6_regex(R"(^([a-fA-F0-9:]+)$)");
    return std::regex_match(ip, ipv6_regex);
}

template <typename T, size_t N>
bool IpManager::calculateIp(std::array<T, N>& current_ip, std::array<T, N>& network_ip, std::array<T, N>& current_mask, int ip_size) {
    if(this->is_first_ip){
        int del_place = this->current_subnet.find("/"); //
        std::string subnet_mask = (del_place ==  static_cast<int>(std::string::npos)) ? std::to_string(ip_size) : this->current_subnet.substr(del_place + 1);
        std::string subnet_addr = (del_place ==  static_cast<int>(std::string::npos)) ? this->current_subnet : this->current_subnet.substr(0, del_place);

        int maskBits = std::stoi(subnet_mask);
        for (int i = 0; i < (int)N; i++) {
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