#include <iostream>
#include <cstring>
#include <cstdlib>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#include "ndpHandler.h"

#define ETH_HDRLEN 14   // Длина Ethernet-заголовка
#define IP6_HDRLEN 40   // Длина IPv6-заголовка
#define ICMP6_HDRLEN 32 // Длина ICMPv6 NS-запроса (без опций)

using namespace std;

#undef socket
#include <sys/socket.h>  // For socket(), bind(), etc.

// Функция для вычисления контрольной суммы ICMPv6
unsigned short checksum(void *b, int len) {    
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

int NDPHandler::sendNDP(unsigned char* dst_ip6) {
    
    struct sockaddr_ll sa;
    memset(this->buffer, 0, sizeof(buffer));

    this->sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
    if (this->sock < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    memset(&sa, 0, sizeof(struct sockaddr_ll));
    sa.sll_protocol = htons(ETH_P_ALL);  
    if ((sa.sll_ifindex = if_nametoindex (this->ifr.ifr_name)) == 0) {
        perror ("if_nametoindex() failed to obtain interface index");
        exit(EXIT_FAILURE);
      }
    sa.sll_halen = ETH_ALEN;

    // ETHER HEADER
    struct ethhdr eth_hdr;
    eth_hdr.h_proto = htons(ETH_P_IPV6);
    memset(eth_hdr.h_dest, 0xff, 6); 
    memcpy(eth_hdr.h_source, NetworkUtils::getMAC(&this->ifr), 6); 

    // IPV6 HEADER
    struct ip6_hdr ip6_hdr;
    ip6_hdr.ip6_flow = htonl(0x60000000); 
    ip6_hdr.ip6_plen = htons(ICMP6_HDRLEN); 
    ip6_hdr.ip6_nxt = IPPROTO_ICMPV6; 
    ip6_hdr.ip6_hlim = 255; 
    memcpy(&ip6_hdr.ip6_src, NetworkUtils::getIP(this->ifr.ifr_name, AF_INET6), 16);
    // inet_pton(AF_INET6, NetworkUtils::getIP(this->ifr.ifr_name, AF_INET6), &ip6_hdr.ip6_src); 
    memcpy(&ip6_hdr.ip6_dst, dst_ip6, 16);

    // ICMP6 HEADER
    struct icmp6_hdr icmp6_hdr;
    icmp6_hdr.icmp6_type = 135; 
    icmp6_hdr.icmp6_code = 0;
    icmp6_hdr.icmp6_cksum = 0; 
    memset(&icmp6_hdr.icmp6_dataun, 0, sizeof(icmp6_hdr.icmp6_dataun));
    inet_pton(AF_INET6, (const char*)dst_ip6, &icmp6_hdr.icmp6_dataun); 
    icmp6_hdr.icmp6_cksum = checksum(&icmp6_hdr, ICMP6_HDRLEN);

    // FILL BUFFER
    memcpy(this->buffer, &eth_hdr, ETH_HDRLEN);
    memcpy(this->buffer + ETH_HDRLEN, &ip6_hdr, IP6_HDRLEN);
    memcpy(this->buffer + ETH_HDRLEN + IP6_HDRLEN, &icmp6_hdr, ICMP6_HDRLEN);
    

    if (sendto(this->sock, this->buffer, sizeof(buffer), 0, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("sendto() failed");
        close(this->sock);
        exit(EXIT_FAILURE);
    }

    cout << "NDP Neighbor Solicitation sent!" << endl;
    close(this->sock);
    return 0;
}

int NDPHandler::receiveNDP(const unsigned char* target_ip) {

    

    while (true) {
        memset(this->buffer, 0, sizeof(buffer));


        int len = recvfrom(this->sock, this->buffer, sizeof(buffer), 0, NULL, NULL);


        if (len < 0) {
            perror("recvfrom() failed");
            close(this->sock);
            exit(EXIT_FAILURE);
        }

        struct ethhdr *eth_hdr = (struct ethhdr*)this->buffer;
        if (ntohs(eth_hdr->h_proto) != ETH_P_IPV6) {
            continue;
        }

        struct ip6_hdr *ip6_hdr = (struct ip6_hdr*)(this->buffer + ETH_HDRLEN);

        if (ip6_hdr->ip6_nxt != IPPROTO_ICMPV6) {
            continue;
        }

        if(memcmp(&ip6_hdr->ip6_dst, NetworkUtils::getIP(this->ifr.ifr_name, AF_INET6), 16) != 0) {
            continue;
        }

        if(memcmp(&ip6_hdr->ip6_src, target_ip, 16) != 0) {
            continue;
        }

        struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr*)(this->buffer + ETH_HDRLEN + IP6_HDRLEN);

        if (icmp6_hdr->icmp6_type != 136) { // NA-запрос
            continue;
        }

        if(memcmp(icmp6_hdr->icmp6_dataun.icmp6_un_data16, NetworkUtils::getMAC(&this->ifr), 6) != 0) {
            continue;
        }

        unsigned char *target_ip6 = (unsigned char*)&icmp6_hdr->icmp6_dataun;
        if (memcmp(target_ip6, NetworkUtils::getIP(this->ifr.ifr_name, AF_INET6), 16) == 0) {
            cout << "Received NDP Neighbor Advertisement for our IP!" << endl;
            break;
        }
    }

    close(this->sock);
    return 0;
}
