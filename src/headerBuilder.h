#ifndef HEADERBUILDER_H
#define HEADERBUILDER_H

#include <iostream>
#include <string>
#include <array>
#include <vector>
#include <cstdio>
#include <arpa/inet.h> 
#include "networkUtils.h"
#include <sys/ioctl.h> 
#include <cstring>  
#include <netinet/ip.h> 
#include <unistd.h> 
#include <netinet/ip_icmp.h> 
#include <netinet/ether.h> 
#include <netinet/if_ether.h> 
#include <net/if.h> 
#include "networkUtils.h" 
#include <netinet/ip6.h> 
#include <netinet/icmp6.h> 


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

// Pseudo header that is used for checksum calculation in ICMPv6 packets
struct pseudo_header{
    struct in6_addr src;
    struct in6_addr dst;
    uint32_t length;
    uint8_t zero[3];
    uint8_t next_header;
};

/**
 * @brief Class that is responsible for building separate parts of the header for the packet. Packet can
 * be configured with different headers according to the used protocol.
 * 
 */
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

            /**
             * @brief Construct a new Ethernet header
             * 
             * @param protocol Protocol
             * @param dst_ip Destination IP address
             * @param dst_mac Destination MAC address
             * @param ifr Interface request structure
             * 
             * @return void
             */
            void buildETH(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr);
            
            /**
             * @brief Get Ethernet header
             * 
             * @return const struct ethhdr* 
             */
            const struct ethhdr* getETHHeader();

            /**
             * @brief Construct a new ARP header
             * 
             * @param protocol Protocol
             * @param dst_ip Destination IP address
             * @param dst_mac Destination MAC address
             * @param ifr Interface request structure
             * 
             * @return void
             */
            void buildARP(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr);

            /**
             * @brief Get ARP header. We have to transform the struct to const struct arphdr* because in arphdr
             * we cannot fill the ar_sha, ar_sip, ar_tha and ar_tip fields, that impotant to send this request.
             * 
             * @return const struct arphdr* 
             */ 
            const struct arphdr* getARPHeader();

            /**
             * @brief Construct a new IP header
             * 
             * @param protocol Protocol
             * @param dst_ip Destination IP address
             * @param dst_mac Destination MAC address
             * @param ifr Interface request structure
             * 
             * @return void
             */
            void buildIP(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr);

            /**
             * @brief Get IP header
             * 
             * @return const struct iphdr*
             */
            const struct iphdr* getIPHeader();

            /**
             * @brief Construct a new ICMP header
             * 
             * @param protocol Protocol
             * @param dst_ip Destination IP address
             * @param dst_mac Destination MAC address
             * @param ifr Interface request structure
             * 
             * @return void
             */
            void buildICMP(int protocol, const unsigned char* dst_ip,const unsigned char* dst_mac, struct ifreq ifr);

            /**
             * @brief Get ICMP header
             * 
             * @return const struct icmp_hdr*
             */
            const struct icmp_hdr* getICMPHeader();

            /**
             * @brief Construct a new IPv6 header
             * 
             * @param protocol Protocol
             * @param dst_ip Destination IP address
             * @param dst_mac Destination MAC address
             * @param ifr Interface request structure
             * 
             * @return void
             */
            void buildIP6(int protocol, const unsigned char* dst_ip,const  unsigned char* dst_mac, struct ifreq ifr);

            /**
             * @brief Get IPv6 header
             * 
             * @return const struct ip6_hdr*
             */
            const struct ip6_hdr* getIP6Header();

            /**
             * @brief Construct a new Neighbor Solicitation header
             * 
             * @param protocol Protocol
             * @param dst_ip Destination IP address
             * @param dst_mac Destination MAC address
             * @param ifr Interface request structure
             * 
             * @return void
             */
            void buildNS(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr);

            /**
             * @brief Get Neighbor Solicitation header
             * 
             * @return const struct nd_neighbor_solicit*
             */
            const struct nd_neighbor_solicit* getNSHeader();

            /**
             * @brief Construct a new ICMPv6 header
             * 
             * @param protocol Protocol
             * @param dst_ip Destination IP address
             * @param dst_mac Destination MAC address
             * @param ifr Interface request structure
             * 
             * @return void
             */
            void buildICMP6(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr);

            /**
             * @brief Get ICMPv6 header
             * 
             * @return const struct icmp6_hdr*
             */
            const struct icmp6_hdr* getICMP6Header();

    };

#endif // HEADERBUILDER_H


