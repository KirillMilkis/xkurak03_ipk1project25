/*
 * File: ipManager.h
 * Author: Kirill Kurakov <xkurak03>
 * Date Created: 
 * Note:
 */
#ifndef IPMANAGER_H
#define IPMANAGER_H

#include <vector>
#include <string>
#include <array>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <bitset>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <algorithm>
#include <cmath>
#include <regex>

#define IPV4_LEN 32
#define IPV6_LEN 128

/**
 * @brief Class that is responsible for all logic with IP addresses (Incrementing, changing subnet, etc.)
 */
class IpManager {
    public: 
        /**
         * @brief Construct a new Ip Manager object
         * 
         * @param subnets Vector of subnets
         */
        IpManager(std::vector<std::string> subnets)
        {  
            for(const auto& subnet : subnets) {

                this->is_ipv6 = false;

                // Push subnets to the correct vector
                if(isIPv6(subnet)) {
                    this->ipv6_subnets.push_back(subnet);
                } else {
                    this->ipv4_subnets.push_back(subnet);
                }

                // Check what type of subnet to use first
                if(this->ipv4_subnets.size() > 0) {
                    this->current_subnet = this->ipv4_subnets[0];
                    this->is_ipv6 = false;
                } else if(this->ipv6_subnets.size() > 0) {
                    this->current_subnet = this->ipv6_subnets[0];
                    this->is_ipv6 = true;
                }
                
                this->current_ip_int = 0;
                this->is_first_ip = true;
                this->subnet_num = 0;
            }
        }

        /**
         * @brief Get next IP address from the subnet
         * 
         * @return unsigned char* Next IP address
         */
        unsigned char* getNextIp();

        /**
         * @brief Use next subnet from the list of subnets
         * 
         * @return bool True if there is another subnet, false otherwise
         */
        bool useNextSubnet();

        /**
         * @brief Get current IP address
         * 
         * @return unsigned char* Current IP address
         */
        unsigned char* getCurrentIp();

        /**
         * @brief Get current IP address as string
         * 
         * @return std::string Current IP address as string
         */
        std::string getCurrentIpString();

        /**
         * @brief Check if the IP address is IPv6
         * 
         * @param ip IP address
         * 
         * @return bool True if the IP address is IPv6, false otherwise
         */
        static bool isIPv6(const std::string& ip);

        /**
         * @brief Print all subnets from the list
         * 
         * @return void
         */
        void printAllSubnets();

    private:
        int subnet_num;
        unsigned int current_ip_int;
        bool is_first_ip;

        std::string current_subnet;
        std::vector<std::string> ipv6_subnets;
        std::vector<std::string> ipv4_subnets;
        
        std::array<uint8_t, 16> current_ipv6;
        std::array<uint8_t, 4> current_mask_ipv4;
        std::array<uint8_t, 16> current_mask_ipv6;
        std::array<uint8_t, 4> current_ipv4;

        std::array<uint8_t, 4> network_ipv4;
        std::array<uint8_t, 16> network_ipv6;

        bool is_ipv6 = false;
        std::vector<unsigned char> network_ip;
        std::vector<unsigned char> current_mask;
        std::vector<unsigned char> current_ip_char;

        /**
         * @brief Convert string to int (Only for IPv4)
         * 
         * @param ip IP address
         * 
         *  @return unsigned int IP address as int
         */
        unsigned int stringToInt(std::string ip);

        /**
         * @brief Convert int to char (Only for IPv4)
         * 
         * @param ip_int IP address as int
         * 
         * @return unsigned char* IP address as char
         */
        unsigned char* intToChar(unsigned int ip_int);

        /**
         * @brief Convert int to string (Only for IPv4)
         * 
         * @param ip_int IP address as int
         * 
         * @return std::string IP address as string
         */
        std::string intToString(unsigned int ip_int);
        
        /**
         * @brief Perform bitwise AND operation on two vectors
         * 
         * @param vector1 First vector
         * @param vector2 Second vector
         * 
         * @return std::array<unsigned char, N> Result of the operation
         */
        template <typename T, size_t N>
        std::array<unsigned char, N> biteAND(const std::array<T, N>& vector1, const std::array<T, N>& vector2);

        /**
         * @brief Check if the IP address is over the maximum value
         * 
         * @return bool True if the IP address is over the maximum value, false otherwise
         */
        bool isOver();

        /**
         * @brief Increment IP address
         * 
         * @param ip IP address
         * 
         * @return void
         */
        template <typename T, size_t N>
        void incrementIP(std::array<T, N>& ip);

        /**
         * @brief Convert string to bytes
         * 
         * @param ip IP address
         * 
         * @return std::array<unsigned char, N> IP address as bytes
         */
        template <size_t N> 
        std::array<unsigned char, N> stringToBytes(const std::string& ip);
        
        /**
         * @brief Convert bytes to string
         * 
         * @param ip IP address as bytes
         * 
         * @return std::string IP address as string
         */
        template <typename T, size_t N>
        std::string bytesToString(std::array<T, N> ip);
        
        /**
         * @brief Convert bytes to char
         * 
         * @param ip IP address as bytes
         * @param size Size of the IP address
         * 
         * @return std::vector<unsigned char> IP address as char
         */
        template <typename T, size_t N>
        std::vector<unsigned char> bytesToChar(std::array<T, N> ip, size_t size);
        
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
        bool calculateIp(std::array<T, N>& current_ip, std::array<T, N>& network_ip, std::array<T, N>& current_mask, int ip_size);
        
        /**
         * @brief Check if the mask is valid (Number from |0.0.0.0/MASK|)
         * 
         * @param subnet_mask Subnet mask
         * @param ip_type Type of IP address (AF_INET or AF_INET6)
         * 
         * @return bool True if it is valid, false otherwise
         */
        bool isValidSubnetMask(const std::string& subnet_mask, int ip_type);

        /**
         * @brief Calculate mask from the subnet mask
         * 
         * @param subnet_mask Subnet mask
         * 
         * @return std::array<T, N> Mask
         */
        template <typename T, size_t N>
        std::array<T, N> calculateMask(std::string subnet_mask);

        /**
         * @brief Check if the IPv4 address is valid
         * 
         * @param ip IP address
         * 
         * @return bool True if it is valid, false otherwise
         */
        bool isValidIPv4(const std::string& ip);

        /**
         * @brief Check if the IPv6 address is valid
         * 
         * @param ip IP address
         * 
         * @return bool True if it is valid, false otherwise
         */
        bool isValidIPv6(const std::string& ip);

        /**
         * @brief Check if it is valid subnet 
         * 
         * @param subnet_mask Subnet mask
         * @param subnet_addr Subnet address
         * @param ip_type Type of IP address (AF_INET or AF_INET6)
         * 
         * @return bool True if it is valid, false otherwise
         */
        bool checkSubnet(std::string subnet_mask, std::string subnet_addr, int ip_type);

        /**
         * @brief Print subnets IpV4 or IpV6
         * 
         * @param subnets_to_print List of subnets to print
         * @param ip_len Length of the IP address
         * @param ip_type Type of IP address (AF_INET or AF_INET6)
         * 
         * @return bool True if successful, false otherwise
         */
        bool printSubnetList(std::vector<std::string> subnets_to_print, int ip_len, int ip_type);

        /**
         * @brief Check if the IP address is the last one in the subnet
         * 
         * @param current_ip_copy Current IP address
         * 
         * @return bool True if it is the last IP address, false otherwise
         */
        template <typename T, size_t N>
        bool checkIfLastIp(std::array<T, N> current_ip_copy, std::array<T, N> network_ip, std::array<T, N> current_mask);
};

#endif // IPMANAGER_H