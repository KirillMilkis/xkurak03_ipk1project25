
#include "transportHandler.h"
#include "Header.cpp"
#include <iostream>
#include <string>
#include <array>
#include <vector>
#include <cstdio>
#include <sys/ioctl.h>
#include <net/if.h>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>

#define SUCCESS_SENDED 3
#define ETHER_HDR_LEN 14
#define ARP_HDR_LEN 28
#define IP4_HDR_LEN 20
#define ICMP_HDR_LEN 8
#define ICMP6_HDR_LEN 8
#define IP6_HDR_LEN 40

#define ARP 1
#define ICMP 2
#define ICMPv6 3
#define NDP 4


int TransportHandler::SendRequest(const unsigned char* ipaddr, const unsigned char* dst_mac) {
    // Function to send     ARP packets

    memcmp(this->dst_ip, ipaddr, 4);
   

    // Broadcast MAC
    struct sockaddr_ll sa;

    int buffer_size;

    // Get the index of the network device

    memset(&sa, 0, sizeof(struct sockaddr_ll));
    sa.sll_protocol = htons(ETH_P_ALL);  
    if ((sa.sll_ifindex = if_nametoindex (this->ifr.ifr_name)) == 0) {
        perror ("if_nametoindex() failed to obtain interface index");
        exit(EXIT_FAILURE);
      }
    sa.sll_halen = ETH_ALEN;

    memset(buffer, 0, ETH_FRAME_LEN);

    switch(this->protocol) {
        case ARP: {

            ETHHeader eth_hdr;
            eth_hdr.build(1, ipaddr, NULL, this->ifr);
            memcpy(buffer, eth_hdr.getHeader(), ETHER_HDR_LEN);

            ARPHeader arp_hdr;
            arp_hdr.build(1, ipaddr, NULL, this->ifr);
            memcpy(buffer + ETHER_HDR_LEN, arp_hdr.getHeader(), ARP_HDR_LEN);

            buffer_size = ETHER_HDR_LEN + ARP_HDR_LEN;
            break;
            
        }
        case ICMP: {
            ETHHeader eth_hdr;
            eth_hdr.build(2, ipaddr, dst_mac, this->ifr);
            memcpy(buffer, eth_hdr.getHeader(), ETHER_HDR_LEN);

            IPHeader ip_hdr;
            ip_hdr.build(2, ipaddr, dst_mac, this->ifr);
            memcpy(buffer + ETHER_HDR_LEN, ip_hdr.getHeader(), IP4_HDR_LEN);
            
            ICMPHeader icmp_hdr;
            icmp_hdr.build(2, ipaddr, dst_mac, this->ifr);
            memcpy(buffer + ETHER_HDR_LEN + IP4_HDR_LEN, icmp_hdr.getHeader(), ICMP_HDR_LEN);

            buffer_size = ETHER_HDR_LEN + IP4_HDR_LEN + ICMP_HDR_LEN;
            break;

        }
        case ICMPv6: {
            ETHHeader eth_hdr;
            eth_hdr.build(3, ipaddr, dst_mac, this->ifr);
            memcpy(buffer, eth_hdr.getHeader(), ETHER_HDR_LEN);

            // IP6Header ip6_hdr = new IP6Header(this->iface);
            // ip6_hdr->build(ipaddr, this->ifr);
            // memet(buffer + ETHER_HDR_LEN, ip6_hdr->getHeader(), IP6_HDR_LEN);
            
            // ICMP6Header  icmp6_hdr = new ICMP6Header(this->iface);
            // icmp6_hdr->build();
            // memet(buffer + ETHER_HDR_LEN + IP6_HDR_LEN, icmp6_hdr->getHeader(), ICMP6_HDR_LEN);

            buffer_size = ETHER_HDR_LEN + IP6_HDR_LEN + ICMP6_HDR_LEN;
            break;

        }

        case NDP: {

            ETHHeader eth_hdr;
            eth_hdr.build(4, ipaddr, dst_mac, this->ifr);
            memcpy(buffer, eth_hdr.getHeader(), ETHER_HDR_LEN);

            // IP6Header ip6_hdr = new IP6Header(this->iface);
            // ip6_hdr->build(ipaddr, this->ifr);
            // memet(buffer + ETHER_HDR_LEN, ip6_hdr->getHeader(), IP6_HDR_LEN);
            
            // ICMP6Header icmp6_hdr = new ICMP6Header(this->iface);
            // icmp6_hdr->build();
            // memet(buffer + ETHER_HDR_LEN + IP6_HDR_LEN, icmp6_hdr->getHeader(), ICMP6_HDR_LEN);

            buffer_size = ETHER_HDR_LEN + IP6_HDR_LEN + ICMP6_HDR_LEN;
            break;
        }

    }
    
    // memset(buffer, 0, ETH_FRAME_LEN);  // Заполняем буфер кадра
    // memcpy(buffer, &eth_hdr, ETHER_HDR_LEN);
    // memcpy(buffer + ETHER_HDR_LEN, &arp_hdr, ARP_HDR_LEN);
    int sock_type = 0;

    switch(this->protocol) {
        case ARP:
            sock_type = ETH_P_ARP;
            break;
        case ICMP:
            sock_type = ETH_P_IP;
            break;
        case ICMPv6:
            sock_type = SOCK_RAW;
            break;
        case NDP:
            sock_type = SOCK_RAW;
            break;
    }

    this->sock = socket(AF_PACKET, SOCK_RAW, htons(sock_type));

    if(this->sock < 0){
        perror("Socket error");
        exit(1);
    }

    if (sendto(this->sock, buffer, buffer_size, 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll)) < 0) {
        perror("sendto() failed");
        exit(EXIT_FAILURE);
    }

    return SUCCESS_SENDED; //
    
}


#include <netinet/if_ether.h>

bool TransportHandler::testArpResponse(const unsigned char* buffer) {

    struct ethhdr* eth_hdr = (struct ethhdr*)buffer;

    if(ntohs(eth_hdr->h_proto) != ETH_P_ARP) {
        // std::cout << "Not an ARP packet" << std::endl;
        return false;
    }

    ARP_HDR* arp_hdr = (ARP_HDR*)(buffer + ETHER_HDR_LEN);

    if(ntohs(arp_hdr->ar_op) != 2){
        // std::cout << "Not an ARP reply" << std::endl;
        return false;
    }

    if(memcmp(arp_hdr->ar_tip, NetworkUtils::getIP(this->ifr.ifr_name, AF_INET), 4) != 0 || memcmp(arp_hdr->ar_tha, NetworkUtils::getMAC(&this->ifr), 6) != 0){
        // std::cout << "Not a response to our request" << std::endl;
        return false;
    }

    return true;
}


bool TransportHandler::testICMPResponse(const unsigned char* buffer){

    struct ethhdr* eth_hdr = (struct ethhdr*)buffer;
    struct iphdr* ip_hdr = (struct iphdr*)(buffer + ETHER_HDR_LEN);
    ICMP_HDR* icmp_hdr = (ICMP_HDR*)(buffer + ETHER_HDR_LEN + IP4_HDR_LEN);

    if(ntohs(eth_hdr->h_proto) != ETH_P_IP) {
        // std::cout << "Not an IP packet" << std::endl;
        return false;
    }

    if(ip_hdr->protocol != IPPROTO_ICMP) {
        // std::cout << "Not an ICMP packet" << std::endl;
        return false;
    }

    if(ip_hdr->daddr != *(uint32_t*)NetworkUtils::getIP(this->ifr.ifr_name, AF_INET) || ip_hdr->saddr != *(uint32_t*)this->dst_ip){
        // std::cout << "Not a response to our request" << std::endl;
        return false;
    }

    if(memcmp(eth_hdr->h_dest, NetworkUtils::getMAC(&this->ifr), 6) != 0) {
        // std::cout << "Not a response to our request" << std::endl;
        return false;
    }

    // if(icmp_hdr->id != this->icmp_hdr_id) {
    //     // std::cout << "Not a response to our request" << std::endl;
    //     return false;
    // }

    if(icmp_hdr->type != 0){
        // std::cout << "Not an icmp ehco reply" << std::endl;
        return false;
    }

    return true;
}




int TransportHandler::ListenToResponce(const unsigned char* target_ip, long int timeout_ms) {

    std::cout << "Listening to response" << std::endl;

    while(1){
        memset(buffer, 0, BUFSIZE);

        struct timeval timeout;
        timeout.tv_sec = timeout_ms / 1000; 
        timeout.tv_usec = (timeout_ms % 1000) * 1000;

        setsockopt(this->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        
        int length = recvfrom(this->sock, this->buffer, BUFSIZE, 0, NULL, NULL);

        if (length < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                return false;
            } else {
                perror("recvfrom() failed");
                break;
            }
        }
        

        ARP_HDR* arp_hdr = (ARP_HDR*)(buffer + ETHER_HDR_LEN);

        switch(this->protocol) {
            case ARP:
                if (!this->testArpResponse(buffer)){
                    continue;
                }
                memcpy(this->dst_mac, arp_hdr->ar_sha, 6);
                break;
            case ICMP:
                if (!this->testICMPResponse(buffer)){
                    continue;
                }
                break;
            case ICMPv6:
                break;
            case NDP:
                break;
        }

       
       

        return SUCCESS_RECEIVED;
    }

    return false;
}

std::string TransportHandler::GetDestMAC() {
    return NetworkUtils::macToString(this->dst_mac);
}
