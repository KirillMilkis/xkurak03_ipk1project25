#include <string>
#include "networkUtils.h"
#include <cstring>

#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>


// class NetworkUtils {    
//     public:

//         static std::string getMAC(struct ifreq* ifr);
//         static std::string getIP();

// };

unsigned char* NetworkUtils::getMAC(struct ifreq* ifr, int sock, unsigned char* mac) {

    if (ioctl(sock, SIOCGIFHWADDR, ifr) < 0) {
        perror ("ioctl() failed to get source MAC address");
        
      }

    memcpy(mac, ifr->ifr_hwaddr.sa_data, 6);
    printf("MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return mac;
}


unsigned char* NetworkUtils::getIP(struct ifreq* ifr, int sock, unsigned char* ipv4) {

    if (ioctl(sock, SIOCGIFADDR, ifr) < 0) {
        perror("IP error");
        return NULL;
    }

    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr->ifr_addr;
    memcpy (ipv4, &ipaddr->sin_addr, 4);

    printf("IP Address: %d.%d.%d.%d\n",
           ipv4[0], ipv4[1], ipv4[2], ipv4[3]);

    return ipv4;

}