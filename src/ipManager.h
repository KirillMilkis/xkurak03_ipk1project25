
#ifndef IPMANAGER_H
#define IPMANAGER_H

#include <vector>
#include <string>
#include <array>
#include <cstdint>
#include <iostream>
#include <ostream>

#define INET6_ADDRSTRLEN 46




class IpManager {
    public: 
        IpManager(std::vector<std::string> subnets)
         {  
            for(const auto& subnet : subnets) {

                this->is_ipv6 = false;

                if(isIPv6(subnet)) {
                    this->ipv6_subnets.push_back(subnet);
                } else {
                    this->ipv4_subnets.push_back(subnet);
                }

                if(this->ipv4_subnets.size() > 0) {
                    this->current_subnet = this->ipv4_subnets[0];
                } else if(this->ipv6_subnets.size() > 0) {
                    this->current_subnet = this->ipv6_subnets[0];
                    std::cout << "Setting ipv6" << std::endl;
                    this->is_ipv6 = true;
                }
             
                this->current_ip_int = 0;
                this->is_first_ip = true;
    
                this->subnet_num = 0;
                }
            }

        unsigned char* getNextIp();
        bool useNextSubnet();
        unsigned char* getCurrentIp();

        std::string getCurrentIpString();
        static bool isIPv6(const std::string& ip);

        int printAllSubnets();
        int printSubnetList(std::vector<std::string> subnets_to_print, int ip_len) ;

    private:
        // std::vector<std::string> subnet;
        std::string current_subnet;
        std::vector<std::string> ipv6_subnets;
        std::vector<std::string> ipv4_subnets;
        int subnet_num;
        unsigned int current_ip_int;
        bool is_first_ip;
        // unsigned char* current_ip = NULL;
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

        unsigned int stringToInt(std::string ip);
        unsigned char* intToChar(unsigned int ip_int);
        std::string intToString(unsigned int ip_int);
        

        template <typename T, size_t N>
        std::array<unsigned char, N> biteAND(const std::array<T, N>& vector1, const std::array<T, N>& vector2);

        bool isOver();

        template <typename T, size_t N>
        void incrementIP(std::array<T, N>& ip);

        template <size_t N> 
        std::array<unsigned char, N> stringToBytes(const std::string& ip);
        
        template <typename T, size_t N>
        std::string bytesToString(std::array<T, N> ip);
        
        template <typename T, size_t N>
        std::vector<unsigned char> bytesToChar(std::array<T, N> ip, size_t size);
        
        template <typename T, size_t N>
        bool calculateIp(std::array<T, N>& current_ip, std::array<T, N>& network_ip, std::array<T, N>& current_mask, int ip_size);
        

};

#endif // IPMANAGER_H