#include <string>
#include "networkUtils.h"
#include <cstring>

#include <ifaddrs.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>



unsigned char* NetworkUtils::mac_addr = NULL;
unsigned char* NetworkUtils::ip_addrv4 = NULL;
unsigned char* NetworkUtils::ip_addrv6 = NULL;

unsigned char* NetworkUtils::getMAC(struct ifreq* ifr) {

    if(NetworkUtils::mac_addr == NULL) {

        NetworkUtils::mac_addr = (unsigned char*)malloc(sizeof(unsigned char) * 6);
        if(NetworkUtils::mac_addr == NULL) {
            perror("malloc() failed");
            return NULL;
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


unsigned char* NetworkUtils::getIP(const char* iface, int family) {

    if (family == AF_INET && NetworkUtils::ip_addrv4) return ip_addrv4;
    if (family == AF_INET6 && NetworkUtils::ip_addrv6) return ip_addrv6;


    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs() failed");
        return nullptr;
    }
   
    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        std::cout << ifa->ifa_name << "ifr name" << std::endl;
        std::cout << iface << "iface" << std::endl;
        std::cout << ifa->ifa_addr->sa_family << "family" << std::endl;
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
                return NetworkUtils::ip_addrv4;
            }
          
            
        }
    }

    freeifaddrs(ifaddr);
    
    return nullptr;

}


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




std::string NetworkUtils::macToString(unsigned char* mac){
    char mac_c[18];
    sprintf(mac_c, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return std::string(mac_c);
}

std::string NetworkUtils::ipToString(const unsigned char* ip){
    char ip_c[16];
    sprintf(ip_c, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

    return std::string(ip_c);
}