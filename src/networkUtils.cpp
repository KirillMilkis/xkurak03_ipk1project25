/*
 * File: networkUtils.cpp
 * Author: Kirill Kurakov <xkurak03>
 * Date Created: XX.03.2025
 * Note:
 */
#include "networkUtils.h"

// Set all static variaables to nullptr 
unsigned char* NetworkUtils::mac_addr = nullptr;
unsigned char* NetworkUtils::ip_addrv4 = nullptr;
unsigned char* NetworkUtils::ip_addrv6 = nullptr;

/**
 * @brief Get MAC address of the interface
 * 
 * @param ifr Interface request structure
 * 
 * @return unsigned char* MAC address
 */
unsigned char* NetworkUtils::getMAC(struct ifreq* ifr) {

    if(NetworkUtils::mac_addr == nullptr) {

        NetworkUtils::mac_addr = (unsigned char*)malloc(sizeof(unsigned char) * 6);
        if(NetworkUtils::mac_addr == nullptr) {
            perror("malloc() failed");
            return nullptr;
        }

        int sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
        if(sock < 0){
            perror("Socket error");
            exit(1);
        }

        if(ioctl(sock, SIOCGIFHWADDR, ifr) < 0) {
            perror ("ioctl() failed to get source MAC address");
            
          }
    
        memcpy(NetworkUtils::mac_addr, ifr->ifr_hwaddr.sa_data, 6);

        close(sock);
   
    }

    return NetworkUtils::mac_addr;
}

/**
 * @brief Get IP address of the interface
 * 
 * @param iface Interface name
 * @param family Address family
 * 
 * @return unsigned char* IP address
 */
unsigned char* NetworkUtils::getIP(const char* iface, int family) {

    if (family == AF_INET && NetworkUtils::ip_addrv4) return ip_addrv4;
    if (family == AF_INET6 && NetworkUtils::ip_addrv6) return ip_addrv6;


    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs() failed");
        return nullptr;
    }
   
    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || strcmp(ifa->ifa_name, iface) != 0) continue;
      
        if (ifa->ifa_addr->sa_family == family) {
            if (family == AF_INET) {  // IPv4
                struct sockaddr_in* ip4 = (struct sockaddr_in*)ifa->ifa_addr;
                if (!NetworkUtils::ip_addrv4) NetworkUtils::ip_addrv4 = (unsigned char*)malloc(4);
                memcpy(ip_addrv4, &ip4->sin_addr, 4);
                freeifaddrs(ifaddr);
                return NetworkUtils::ip_addrv4;
            } 
            else if (family == AF_INET6) {  // IPv6
                struct sockaddr_in6* ip6 = (struct sockaddr_in6*)ifa->ifa_addr;
                if (!NetworkUtils::ip_addrv6) NetworkUtils::ip_addrv6 = (unsigned char*)malloc(16);
                memcpy(NetworkUtils::ip_addrv6, &ip6->sin6_addr, 16);
                freeifaddrs(ifaddr);
                return NetworkUtils::ip_addrv6;
            }
          
            
        }
    }

    // Check if interface exitsts
    if(NetworkUtils::ip_addrv4 == nullptr && NetworkUtils::ip_addrv6 == nullptr){
        std::cout << "Ip in this interface not found " << std::endl; //
        exit(1);
    }

    freeifaddrs(ifaddr);
    
    return nullptr;

}

/**
 * @brief Calculate checksum of the header
 * 
 * @param b Packet
 * @param len Length of the header
 * 
 * @return unsigned short Checksum
 */
unsigned short NetworkUtils::checksum(void *b, int len) {    
    unsigned short *buf = (unsigned short*)b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }

    if (len == 1) {
        sum += *(unsigned char*)buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}

/**
 * @brief Convert MAC address to string
 * 
 * @param mac MAC address as unsigned char*
 * 
 * @return std::string MAC address as string
 */
std::string NetworkUtils::macToString(unsigned char* mac){
    char mac_c[18];
    sprintf(mac_c, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return std::string(mac_c);
}

/**
 * @brief Convert IP address to string
 * 
 * @param ip IP address as unsigned char*
 * @param family Address family to determine the IP version
 * 
 * @return std::string IP address as string
 */
std::string NetworkUtils::ipToString(const unsigned char* ip, int family) {
    char ip_c[INET6_ADDRSTRLEN];

    if (family == AF_INET) {  // IPv4
        snprintf(ip_c, sizeof(ip_c), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    } else if (family == AF_INET6) {  // IPv6
        inet_ntop(AF_INET6, ip, ip_c, sizeof(ip_c));
    } else {
        return "Invalid IP family";
    }

    return std::string(ip_c);
}

#include <sstream>


/**
 * @brief Convert MAC address string to bytes
 * 
 * @param macStr MAC address as string
 * @param macBytes MAC address as unsigned char*
 * 
 * @return bool True if conversion was successful, false otherwise
 */
bool NetworkUtils::macStringToBytes(const std::string& macStr, unsigned char* macBytes) {
    std::istringstream iss(macStr);
    std::vector<int> bytes;
    std::string byteStr;

    while (std::getline(iss, byteStr, ':')) {
        int byte;
        std::istringstream(byteStr) >> std::hex >> byte;
        if (byte < 0x00 || byte > 0xFF) return false;
        bytes.push_back(byte);
    }

    if (bytes.size() != 6) return false;

    for (size_t i = 0; i < 6; i++) {
        macBytes[i] = static_cast<unsigned char>(bytes[i]);
    }

    return true;
}

/**
 * @brief Get all interfaces
 * 
 * @return pcap_if_t* All interfaces
 */
pcap_if_t* NetworkUtils::get_interfaces() {
    pcap_if_t *allinfs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if(pcap_findalldevs(&allinfs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(EXIT_FAILURE);

    }
    return allinfs;
}

/**
 * @brief Print all active interfaces
 * 
 * @return int 0 if successful
 */
void NetworkUtils::print_active_interfaces() {
    pcap_if_t *alldevsp;
    alldevsp = NetworkUtils::get_interfaces();
    std::cout << "Active interfaces:" << std::endl;
     while(alldevsp != NULL) {
        std::cout << alldevsp->name << std::endl;

        if(alldevsp->description != NULL) {
            std::cout << alldevsp->description << std::endl;
        } else{
            std::cout << "No description available" << std::endl;
        }

        alldevsp = alldevsp->next;

    }
    
    pcap_freealldevs(alldevsp);

}
