/*
 * File: ipManager.cpp
 * Author: Kirill Kurakov <xkurak03>
 * Date Created: 
 * Note:
 */
#include "ipManager.h"

/**
 * @brief Use next subnet from the list of subnets
 * 
 * @return bool True if there is another subnet, false otherwise
 */
bool IpManager::useNextSubnet() {
    
    this->subnet_num += 1;

    // Decide if the next subnet is IPv4 or IPv6 by the size of the list 
    if(this->subnet_num < (int)this->ipv4_subnets.size()) {
        this->current_subnet = this->ipv4_subnets[this->subnet_num];
        // It will be the first IP in the subnet, flag for the getNextIp function
        this->is_first_ip = true;
    } else if((this->subnet_num - this->ipv4_subnets.size()) < this->ipv6_subnets.size()) {
        this->is_ipv6 = true;
        this->current_subnet = this->ipv6_subnets[this->subnet_num - this->ipv4_subnets.size()];
        // It will be the first IP in the subnet, flag for the getNextIp function
        this->is_first_ip = true;
    } else {
        return false;
    }
    
    // May be by the error new subnet is not valid
    if(!this->current_subnet.empty()) { 
        return true;
    }

    return false;

}

/**
 * @brief Check if it is valid subnet 
 * 
 * @param subnet_mask Subnet mask
 * @param subnet_addr Subnet address
 * @param ip_type Type of IP address (AF_INET or AF_INET6)
 * 
 * @return bool True if it is valid, false otherwise
 */
bool IpManager::checkSubnet(std::string subnet_mask, std::string subnet_addr, int ip_type) {

    if(!this->isValidSubnetMask(subnet_mask, ip_type)){
        std::cerr << "Invalid subnet mask" << std::endl;
        return false;
    }

    if(!(ip_type == AF_INET6 ? this->isValidIPv6(subnet_addr) : this->isValidIPv4(subnet_addr))) {
        std::cerr << "Invalid IP address" << std::endl;
        return false; 
    }

    return true;
}


/**
 * @brief Print subnets IpV4 or IpV6
 * 
 * @param subnets_to_print List of subnets to print
 * @param ip_len Length of the IP address
 * @param ip_type Type of IP address (AF_INET or AF_INET6)
 * 
 * @return bool True if successful, false otherwise
 */
bool IpManager::printSubnetList(std::vector<std::string> subnets_to_print, int ip_len, int ip_type) { //
    
    int del_place;
    int ip_count = 0;

    for(std::string subnet : subnets_to_print){

        del_place = subnet.find("/");
        // Separate subnet address and subnet mask from the |0.0.0.0/24| format
        std::string subnet_mask = (del_place ==  static_cast<int>(std::string::npos)) ? std::to_string(ip_len) : subnet.substr(del_place + 1);
        std::string subnet_addr = (del_place ==  static_cast<int>(std::string::npos)) ? subnet : subnet.substr(0, del_place);

        if(!this->checkSubnet(subnet_mask, subnet_addr, ip_type)) return false; 

        // if it is Ipv4 there are 2 adresses reserved for the network and broadcast
        if (ip_type == AF_INET) ip_count = ip_count - 2;

        // Calculate the number of IP addresses in the subnet
        // 32 or 128 means that mask is not specified, so there is only one IP address
        // otherwise = (IP_LEN - subnet_mask)^2
        ip_count = (std::stoi(subnet_mask) == 32 || std::stoi(subnet_mask) == 128) ? 1 
                      : ip_count + (static_cast<int>(std::pow(2, ip_len - std::stoi(subnet_mask))));

        
        printf("%s %d\n", subnet_addr.c_str(), ip_count);
    }

    return true;
}

/**
 * @brief Print all subnets from the list
 * 
 * @return void
 */
void IpManager::printAllSubnets(){

    printf("Scanning ranges:\n");

    // Separate function to print subnets for IPv4 and IPv6
    if(!this->printSubnetList(this->ipv4_subnets, IPV4_LEN, AF_INET)) exit(EXIT_FAILURE);
    
    if(!this->printSubnetList(this->ipv6_subnets, IPV6_LEN, AF_INET6)) exit(EXIT_FAILURE);

    printf("\n");

}

/**
 * @brief Check if the mask is valid (Number from |0.0.0.0/MASK|)
 * 
 * @param subnet_mask Subnet mask
 * @param ip_type Type of IP address (AF_INET or AF_INET6)
 * 
 * @return bool True if it is valid, false otherwise
 */
bool IpManager::isValidSubnetMask(const std::string& subnet_mask, int ip_type) {
    std::regex mask_regex(R"(^\d{1,3}$)"); // Number from 0 to 128
    if (!std::regex_match(subnet_mask, mask_regex)) {
        return false;
    }

    int mask = std::stoi(subnet_mask);

    if(ip_type == AF_INET6) {
        return mask >= 0 && mask <= 128;
    } else if(ip_type == AF_INET){
        return mask >= 0 && mask <= 32;
    }

    return false;
}

/**
 * @brief Check if the IPv4 address is valid
 * 
 * @param ip IP address
 * 
 * @return bool True if it is valid, false otherwise
 */
bool IpManager::isValidIPv4(const std::string& ip) {
    std::regex ipv4_regex(R"(^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$)"); // BYTE.BYTE.BYTE.BYTE
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

/**
 * @brief Check if the IPv6 address is valid
 * 
 * @param ip IP address
 * 
 * @return bool True if it is valid, false otherwise
 */
bool IpManager::isValidIPv6(const std::string& ip) {
    std::regex ipv6_regex(R"(^([a-fA-F0-9:]+)$)"); // HEX:HEX:HEX:HEX:HEX:HEX:HEX:HEX
    return std::regex_match(ip, ipv6_regex);
}

/**
 * @brief calculate IP address from the subnet address and mask
 * 
 * @param current_ip Current IP address
 * @param network_ip Network IP address
 * @param current_mask Current mask
 * @param ip_size Size of the IP address (32 or 128)
 * 
 * @return bool True if the IP address was calculated, false otherwise
 */
template <typename T, size_t N>
bool IpManager::calculateIp(std::array<T, N>& current_ip, std::array<T, N>& network_ip, std::array<T, N>& current_mask, int ip_size) {
    // If it is first ip calculate network ip, mask and first ip
    if(this->is_first_ip){
        int del_place = this->current_subnet.find("/"); //
        //  // Separate subnet address and subnet mask from the |0.0.0.0/24| format
        std::string subnet_mask = (del_place ==  static_cast<int>(std::string::npos)) ? std::to_string(ip_size) : this->current_subnet.substr(del_place + 1);
        std::string subnet_addr = (del_place ==  static_cast<int>(std::string::npos)) ? this->current_subnet : this->current_subnet.substr(0, del_place);

        // Calculate the mask
        current_mask = this->calculateMask<T,N>(subnet_mask);

        current_ip = this->stringToBytes<N>(subnet_addr);
        // Network IP = current IP & current mask
        network_ip = this->biteAND(current_ip, current_mask);
        current_ip = network_ip;

        // If the Ip is not alone(without specified mask), first address is network address + 1;
        if(!std::all_of(current_mask.begin(), current_mask.end(), [](unsigned char c){ return c == 0xFF; })) {
            if(!this->is_ipv6){
                this->incrementIP(current_ip);
            }

        }

        this->is_first_ip = false;


    } else {
        // If it is not first IP, increment the current IP
        this->incrementIP(current_ip);
        // Test if the IP is in the subnet (IP & MASK == NETWORK IP & MASK). If it is not overflowed to the mask bits
        if(!this->checkIfLastIp(current_ip, network_ip, current_mask)) return false;
        
        // Check if it is 255.255.255.255 or FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF
        if(this->isOver()) return false;
    }

    return true;
}

/**
 * @brief Check if the IP address is the last one in the subnet
 * 
 * @param current_ip_copy Current IP address
 * 
 * @return bool True if it is the last IP address, false otherwise
 */
template <typename T, size_t N>
bool IpManager::checkIfLastIp(std::array<T, N> current_ip_copy, std::array<T, N> network_ip, std::array<T, N> current_mask){
    // If IPv4 increment ip one more time to check that it is not the last available Ip, because last available is reserved for broadcast
    if(!this->is_ipv6){
        this->incrementIP(current_ip_copy);
    }

    if(this->biteAND(network_ip, current_mask) != this->biteAND(current_ip_copy, current_mask)) {
        return false;
    }

    return true;
}

/**
 * @brief Calculate mask from the subnet mask
 * 
 * @param subnet_mask Subnet mask
 * 
 * @return std::array<T, N> Mask
 */
template <typename T, size_t N>
std::array<T, N> IpManager::calculateMask(std::string subnet_mask) {
    std::array<T, N> mask;
    int maskBits = std::stoi(subnet_mask);
    for (size_t i = 0; i < N; i++) {
        if (maskBits >= 8) {
            mask[i] = 0xFF;
            maskBits -= 8;
        } else if (maskBits > 0) {
            mask[i] = (0xFF << (8 - maskBits)) & 0xFF;
            break;
        } else {
            mask[i] = 0;
        }
    }
    return mask;
}

/**
 * @brief Get next IP address from the subnet
 * 
 * @return unsigned char* Next IP address
 */
unsigned char* IpManager::getNextIp() {

    if(!this->is_ipv6){
        if (!calculateIp(this->current_ipv4, this->network_ipv4, this->current_mask_ipv4, IPV4_LEN)){
            return nullptr;
        }      

    } else {
        if(!calculateIp(this->current_ipv6, this->network_ipv6, this->current_mask_ipv6, IPV6_LEN)){
            return nullptr;
        }
    }

    // Convert IP address to char* and return it
    if (this->is_ipv6) {
        this->current_ip_char = bytesToChar<unsigned char, 16>(this->current_ipv6, 16);
    } else {
        this->current_ip_char = bytesToChar<unsigned char, 4>(this->current_ipv4, 4);
    }

    return this->current_ip_char.data();
}

/**
 * @brief Check if the IP address is over the maximum value
 * 
 * @return bool True if the IP address is over the maximum value, false otherwise
 */
bool IpManager::isOver() {
    int fullOctets = 0;
    // FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF
    if(this->is_ipv6) {
        for (auto& octet : this->current_ipv6) {
            if (octet == 0xFF) {
                fullOctets++;
            }
        }
        return fullOctets == 16;
    // FF.FF.FF.FF
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

/**
 * @brief Perform bitwise AND operation on two vectors
 * 
 * @param vector1 First vector
 * @param vector2 Second vector
 * 
 * @return std::array<unsigned char, N> Result of the operation
 */
template <typename T, size_t N>
std::array<unsigned char, N> IpManager::biteAND(const std::array<T, N>& vector1, const std::array<T, N>& vector2) {
    std::array<unsigned char, N> result;
    for (size_t i = 0; i < N; i++) {
        result[i] = vector1[i] & vector2[i];
    }
    return result;
}

/**
 * @brief Increment IP address
 * 
 * @param ip IP address
 * 
 * @return void
 */
template <typename T, size_t N>
void IpManager::incrementIP(std::array<T, N>& ip) {
    for (int i = N - 1; i >= 0; --i) {
        // If the octet is not 255, increment it and break the loop
        if (++ip[i] != 0) break;
    }
}

/**
 * @brief Convert string to bytes
 * 
 * @param ip IP address
 * 
 * @return std::array<unsigned char, N> IP address as bytes
 */
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

/**
 * @brief Convert bytes to string
 * 
 * @param ip IP address as bytes
 * 
 * @return std::string IP address as string
 */
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

/**
 * @brief Convert bytes to char
 * 
 * @param ip IP address as bytes
 * @param size Size of the IP address
 * 
 * @return std::vector<unsigned char> IP address as char
 */
template <typename T, size_t N>
std::vector<unsigned char> IpManager::bytesToChar(std::array<T, N> ip, size_t size) {
    char temp_buffer[INET6_ADDRSTRLEN];
    if (inet_ntop(this->is_ipv6 ? AF_INET6 : AF_INET, ip.data(), temp_buffer, sizeof(temp_buffer)) == nullptr) {
        exit(1);
    }

    std::vector<unsigned char> buffer(temp_buffer, temp_buffer + size);
    return buffer;
}

/**
 * @brief Convert string to int (Only for IPv4)
 * 
 * @param ip IP address
 * 
 *  @return unsigned int IP address as int
 */
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

/**
 * @brief Convert int to char (Only for IPv4)
 * 
 * @param ip_int IP address as int
 * 
 * @return unsigned char* IP address as char
 */
unsigned char* IpManager::intToChar(unsigned int ip_int) {

    unsigned char* result = (unsigned char*)malloc(sizeof(unsigned char) * 4);

    for(int i = 0; i < 4; i++) {
        result[i] = static_cast<unsigned char>((ip_int >> (24 - i * 8)) & 0xFF);
    }

    return result; 

}

/**
 * @brief Convert int to string (Only for IPv4)
 * 
 * @param ip_int IP address as int
 * 
 * @return std::string IP address as string
 */
std::string IpManager::intToString(unsigned int ip_int) {
    std::string result = std::to_string((ip_int >> 24) & 0xFF) + "." + std::to_string((ip_int >> 16) & 0xFF) + "." + std::to_string((ip_int >> 8) & 0xFF) + "." + std::to_string(ip_int & 0xFF);
    return result;
}

/**
 * @brief Get current IP address
 * 
 * @return unsigned char* Current IP address
 */
unsigned char* IpManager::getCurrentIp() {
    return this->is_ipv6 ? this->current_ipv6.data() : this->current_ipv4.data();
}

/**
 * @brief Get current IP address as string
 * 
 * @return std::string Current IP address as string
 */
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

/**
 * @brief Check if the IP address is IPv6
 * 
 * @param ip IP address
 * 
 * @return bool True if the IP address is IPv6, false otherwise
 */
bool IpManager::isIPv6(const std::string& ip) {
    return ip.find(":") != std::string::npos;
}