#include "icmpHandler.h"

#include <netinet/ip.h> // Include this header for the iphdr structure



unsigned short ICMPHandler::checksum(void *b, int len) {    
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

#define SUCCESS_SENDED 0

#define IP4_HDR_LEN 20
#define ETHER_HDR_LEN 14
#define ICMP_HDR_LEN 8

int ICMPHandler::SendICMP(const unsigned char* target_ip, const unsigned char* target_mac) {

    // std::cout << "Sending ICMP packet" << std::endl;

    struct sockaddr_in addr;
    ICMP_HDR icmp_hdr;
    struct sockaddr_ll sa;
    ETH_HDR eth_hdr;
    struct iphdr ip_hdr;

    this->sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if(this->sock < 0){
        perror("Socket error");
        exit(1);
    }

    memset(&sa, 0, sizeof(struct sockaddr_ll));
    sa.sll_protocol = htons(ETH_P_IP);  
 
    if ((sa.sll_ifindex = if_nametoindex (this->ifr.ifr_name)) == 0) {
        perror ("if_nametoindex() failed to obtain interface index");
        exit(EXIT_FAILURE);
    }
    sa.sll_halen = ETH_ALEN;

    // ETHERNET HEADER ------------------------------------------------
    memset(&eth_hdr, 0, sizeof(eth_hdr));
    memcpy(eth_hdr.dest, target_mac, 6);
    memcpy(eth_hdr.src, NetworkUtils::getMAC(&ifr), 6);
    eth_hdr.type = htons(ETH_P_IP);  // ARP 

    // IP HEADER ------------------------------------------------
    memset(&ip_hdr, 0, sizeof(ip_hdr));
    ip_hdr.ihl = 5;
    ip_hdr.version = 4;
    ip_hdr.tos = 0;
    ip_hdr.tot_len = htons(IP4_HDR_LEN + ICMP_HDR_LEN);
    ip_hdr.id = getpid();
    ip_hdr.frag_off = 0;
    ip_hdr.ttl = 255;
    ip_hdr.protocol = IPPROTO_ICMP;
    memcpy(&ip_hdr.saddr, NetworkUtils::getIP(this->ifr.ifr_name, AF_INET), 4);
    memcpy(&ip_hdr.daddr, target_ip, 4);
    ip_hdr.check = checksum(&ip_hdr, sizeof(ip_hdr));
    

    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.type = 8;
    icmp_hdr.code = 0;
    this->icmp_hdr_id = getpid();
    icmp_hdr.id = this->icmp_hdr_id;
    icmp_hdr.seq = htons(1);
    icmp_hdr.checksum = ICMPHandler::checksum(&icmp_hdr, sizeof(icmp_hdr));

    memcpy(this->buffer, &eth_hdr, sizeof(eth_hdr));
    memcpy(this->buffer + sizeof(eth_hdr), &ip_hdr, sizeof(ip_hdr));
    memcpy(this->buffer + sizeof(eth_hdr) + sizeof(ip_hdr), &icmp_hdr, sizeof(icmp_hdr));

    if(sendto(this->sock, buffer, ETHER_HDR_LEN + IP4_HDR_LEN + ICMP_HDR_LEN, 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll)) < 0){
        perror("sendto() failed");
        exit(EXIT_FAILURE);
    }

    // std::cout << "ICMP packet sent" << std::endl;

    return SUCCESS_SENDED;

}


bool ICMPHandler::ListenToResponce(const unsigned char* ipaddr, long int timeout_ms){

    while(1){
        memset(this->buffer, 0, BUFSIZE);

        // std::cout << "Listen to ICMP reply" << std::endl;

        struct timeval timeout;
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = timeout_ms % 1000 * 1000;

        setsockopt(this->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

        int  length = recvfrom(this->sock,  this->buffer, BUFSIZE,  0,  NULL,  NULL);

        if (length < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                // std::cout << "Timeout waiting for ICMP reply..." << std::endl;
                return false;
            } else {
                perror("recvfrom() failed");
                break;
            }
        }

        ETH_HDR* eth_hdr = (ETH_HDR*)buffer;
        struct iphdr* ip_hdr = (struct iphdr*)(buffer + ETHER_HDR_LEN);
        ICMP_HDR* icmp_hdr = (ICMP_HDR*)(buffer + ETHER_HDR_LEN + IP4_HDR_LEN);

        if(ntohs(eth_hdr->type) != ETH_P_IP) {
            // std::cout << "Not an IP packet" << std::endl;
            continue;
        }

        if(ip_hdr->protocol != IPPROTO_ICMP) {
            // std::cout << "Not an ICMP packet" << std::endl;
            continue;
        }

        if(ip_hdr->daddr != *(uint32_t*)NetworkUtils::getIP(this->ifr.ifr_name, AF_INET) || ip_hdr->saddr != *(uint32_t*)ipaddr){
            // std::cout << "Not a response to our request" << std::endl;
            continue;
        }

        if(memcmp(eth_hdr->dest, NetworkUtils::getMAC(&ifr), 6) != 0) {
            // std::cout << "Not a response to our request" << std::endl;
            continue;
        }

        if(icmp_hdr->id != this->icmp_hdr_id) {
            // std::cout << "Not a response to our request" << std::endl;
            continue;
        }

        if(icmp_hdr->type != 0){
            // std::cout << "Not an icmp ehco reply" << std::endl;
            continue;
        }

        // std::cout << "ICMP reply received" << std::endl;

        return true;

    }

}


// int ICMPHandler::SendICMPv6(const unsigned char* target_ip, const unsigned char* target_mac) {

//     struct sockaddr_in6 addr;
//     ICMPV6_HDR icmpv6_hdr;
//     struct sockaddr_ll sa;
//     ETH_HDR eth_hdr;
//     struct ip6_hdr ip6_hdr;

//     this->sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
//     if(this->sock < 0){
//         perror("Socket error");
//         exit(1);
//     }

//     memset(&sa, 0, sizeof(struct sockaddr_ll));
//     sa.sll_protocol = htons(ETH_P_IPV6);  
 
//     if ((sa.sll_ifindex = if_nametoindex (this->ifr.ifr_name)) == 0) {
//         perror ("if_nametoindex() failed to obtain interface index");
//         exit(EXIT_FAILURE);
//     }
//     sa.sll_halen = ETH_ALEN;

//     // ETHERNET HEADER ------------------------------------------------
//     memset(&eth_hdr, 0, sizeof(eth_hdr));
//     memcpy(eth_hdr.dest, target_mac, 6);
//     memcpy(eth_hdr.src, NetworkUtils::getMAC(&ifr), 6);
//     eth_hdr.type = htons(ETH_P_IPV6);

//     // IPv6 HEADER ------------------------------------------------
//     memset(&ip6_hdr, 0, sizeof(ip6_hdr));
//     ip6_hdr.ip6_flow = htonl((6 << 28) | (0 << 20) | 0);
//     ip6_hdr.ip6_plen = htons(ICMPV6_HDR_LEN);
//     ip6_hdr.ip6_nxt = IPPROTO_ICMPV6;
//     ip6_hdr.ip6_hops = 255;
//     memcpy(&ip6_hdr.ip6_src, NetworkUtils::getIP(this->ifr.ifr_name, AF_INET6), 16);
//     memcpy(&ip6_hdr.ip6_dst, target_ip, 16);

//     memset(&icmpv6_hdr, 0, sizeof(icmpv6_hdr));
//     icmpv6_hdr.type = 128; // Echo Request
//     icmpv6_hdr.code = 0;
//     this->icmp_hdr_id = getpid();
//     icmpv6_hdr.id = this->icmp_hdr_id;
//     icmpv6_hdr.seq = htons(1);
//     icmpv6_hdr.checksum = 0; // Checksum will be calculated later

//     // Calculate ICMPv6 checksum
//     struct {
//         struct in6_addr src;
//         struct in6_addr dst;
//         uint32_t length;
//         uint8_t zero[3];
//         uint8_t next_header;
//     } pseudo_header;

//     memset(&pseudo_header, 0, sizeof(pseudo_header));
//     memcpy(&pseudo_header.src, &ip6_hdr.ip6_src, sizeof(struct in6_addr));
//     memcpy(&pseudo_header.dst, &ip6_hdr.ip6_dst, sizeof(struct in6_addr));
//     pseudo_header.length = htonl(ICMPV6_HDR_LEN);
//     pseudo_header.next_header = IPPROTO_ICMPV6;

//     unsigned char checksum_buffer[sizeof(pseudo_header) + sizeof(icmpv6_hdr)];
//     memcpy(checksum_buffer, &pseudo_header, sizeof(pseudo_header));
//     memcpy(checksum_buffer + sizeof(pseudo_header), &icmpv6_hdr, sizeof(icmpv6_hdr));

//     icmpv6_hdr.checksum = ICMPHandler::checksum(checksum_buffer, sizeof(checksum_buffer));

//     memcpy(this->buffer, &eth_hdr, sizeof(eth_hdr));
//     memcpy(this->buffer + sizeof(eth_hdr), &ip6_hdr, sizeof(ip6_hdr));
//     memcpy(this->buffer + sizeof(eth_hdr) + sizeof(ip6_hdr), &icmpv6_hdr, sizeof(icmpv6_hdr));

//     if(sendto(this->sock, buffer, ETHER_HDR_LEN + sizeof(ip6_hdr) + ICMPV6_HDR_LEN, 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll)) < 0){
//         perror("sendto() failed");
//         exit(EXIT_FAILURE);
//     }

//     return SUCCESS_SENDED;
// }


// bool ICMPHandler::ListenToResponceV6(const unsigned char* ipaddr, long int timeout_ms) {

//     while (1) {
//         memset(this->buffer, 0, BUFSIZE);

//         struct timeval timeout;
//         timeout.tv_sec = timeout_ms / 1000;
//         timeout.tv_usec = timeout_ms % 1000 * 1000;

//         setsockopt(this->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

//         int length = recvfrom(this->sock, this->buffer, BUFSIZE, 0, NULL, NULL);

//         if (length < 0) {
//             if (errno == EWOULDBLOCK || errno == EAGAIN) {
//                 return false;
//             } else {
//                 perror("recvfrom() failed");
//                 break;
//             }
//         }

//         ETH_HDR* eth_hdr = (ETH_HDR*)buffer;
//         struct ip6_hdr* ip6_hdr = (struct ip6_hdr*)(buffer + ETHER_HDR_LEN);
//         ICMPV6_HDR* icmpv6_hdr = (ICMPV6_HDR*)(buffer + ETHER_HDR_LEN + sizeof(struct ip6_hdr));

//         if (ntohs(eth_hdr->type) != ETH_P_IPV6) {
//             continue;
//         }

//         if (ip6_hdr->ip6_nxt != IPPROTO_ICMPV6) {
//             continue;
//         }

//         if (memcmp(&ip6_hdr->ip6_dst, NetworkUtils::getIP(this->ifr.ifr_name, AF_INET6), 16) != 0 || 
//             memcmp(&ip6_hdr->ip6_src, ipaddr, 16) != 0) {
//             continue;
//         }

//         if (memcmp(eth_hdr->dest, NetworkUtils::getMAC(&ifr), 6) != 0) {
//             continue;
//         }

//         if (icmpv6_hdr->id != this->icmp_hdr_id) {
//             continue;
//         }

//         if (icmpv6_hdr->type != 129) { // Echo Reply
//             continue;
//         }

//         return true;
//     }
// }