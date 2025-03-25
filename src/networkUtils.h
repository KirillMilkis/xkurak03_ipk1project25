
#ifndef NETWORKUTILS_H
#define NETWORKUTILS_H

#include <iostream>
#include <array>

#include <unistd.h>  

#define ARP 1
#define ICMP 2
#define ICMPv6 4
#define NDP 3


#define BUFSIZE 100
// #define ETHER_HDR_LEN 14
#define ARP_HDR_LEN 28
#define IP4_HDR_LEN 20
#define ICMP_HDR_LEN 8
#define ICMP6_HDR_LEN 32
#define IP6_HDR_LEN 40

// #define IP4_HDR_LEN 20
// #define ICMP_HDR_LEN 8
// #define ARP_HDR_LEN 28
// #define ICMP6_HDR_LEN 32 
// #define IP6_HDR_LEN 40

class NetworkUtils {
    private:
        static unsigned char* ip_addrv4;
        static unsigned char* ip_addrv6;
        static unsigned char* mac_addr;

    public:
    static unsigned char* getIP(const char* iface, int family);
    static unsigned char* getMAC(struct ifreq* ifr);

    static unsigned short checksum(void *b, int len);

    static std::string macToString(unsigned char* mac);
    static std::string ipToString(const unsigned char* ip, int family);

    static bool macStringToBytes(const std::string& macStr, unsigned char macBytes[6]);

    static pcap_if_t* get_interfaces();

    int print_active_interfaces();

};



#endif // NETWORKUTILS_H