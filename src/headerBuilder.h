#ifndef HEADERBUILDER_H
#define HEADERBUILDER_H

#include <iostream>
#include <string>
#include <array>
#include <vector>
#include <cstdio>
#include <sys/ioctl.h>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h> // for iphdr
#include <unistd.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <net/if.h> // for struct ifreq
#include "networkUtils.h"
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

// #define IP4_HDR_LEN 20
// #define ICMP_HDR_LEN 8
// #define ARP_HDR_LEN 28
// #define ICMP6_HDR_LEN 32 
// #define IP6_HDR_LEN 40


typedef struct ARP_Header {
    uint16_t ar_hrd;   // Hardware type (Ethernet = 1)
    uint16_t ar_pro;   // Protocol type (IPv4 = 0x0800)
    uint8_t ar_hln;    // Hardware address length (MAC = 6)
    uint8_t ar_pln;    // Protocol address length (IPv4 = 4)
    uint16_t ar_op;    // Operation (1 = request, 2 = reply)

    uint8_t ar_sha[6]; // Sender MAC address
    uint8_t ar_sip[4]; // Sender IP address
    uint8_t ar_tha[6]; // Target MAC address
    uint8_t ar_tip[4]; // Target IP address
} ARP_HDR;


typedef struct icmp_hdr {
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned short id;
    unsigned short seq;
} ICMP_HDR;

struct pseudo_header{
    struct in6_addr src;
    struct in6_addr dst;
    uint32_t length;
    uint8_t zero[3];
    uint8_t next_header;
};


class HeaderBuilder {

        private:
            struct ethhdr eth_hdr;
            struct iphdr ip_hdr;
            struct ifreq ifr;
            int protocol;
            ARP_HDR arp_hdr;   
            struct icmp_hdr icmp_hdr;
            int icmp_hdr_id;
            struct ip6_hdr ip6_hdr;
            struct icmp6_hdr icmpv6_hdr;
            struct nd_neighbor_solicit ns;

            const unsigned char broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; 

        public:
            void buildETH(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr);

            const struct ethhdr* getETHHeader();

            void buildARP(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr);

            const struct arphdr* getARPHeader();

            void buildIP(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr);

            const struct iphdr* getIPHeader();

            void buildICMP(int protocol, const unsigned char* dst_ip,const unsigned char* dst_mac, struct ifreq ifr);

            const struct icmp_hdr* getICMPHeader();

            void buildIP6(int protocol, const unsigned char* dst_ip,const  unsigned char* dst_mac, struct ifreq ifr);

            const struct ip6_hdr* getIP6Header();

            void buildNS(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr);

            const struct nd_neighbor_solicit* getNSHeader();

            void buildICMP6(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr);

            const struct icmp6_hdr* getICMP6Header();

    };

#endif // HEADERBUILDER_H


