
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

#include <netinet/if_ether.h>  // ETH_P_ALL

#include <linux/if_packet.h>  // sockaddr_ll

#include "arpHandler.h"


#define SUCCESS_SENDED 0
#define ARP_REPLY 2


int ARPHandler::SendARP(unsigned char* dst_ip) {

    // Function to send ARP packets
    std::cout << "Sending ARP packet" << std::endl;

    ETH_HDR eth_hdr;
    ARP_HDR arp_hdr;
    const unsigned char broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // Broadcast MAC
    struct sockaddr_ll sa;

    // Get the index of the network device

    memset(&sa, 0, sizeof(struct sockaddr_ll));
    sa.sll_protocol = htons(ETH_P_ALL);  
    std::cout << "Interface name: " << this->ifr.ifr_name << std::endl;
    if ((sa.sll_ifindex = if_nametoindex (this->ifr.ifr_name)) == 0) {
        perror ("if_nametoindex() failed to obtain interface index");
        exit(EXIT_FAILURE);
      }
    sa.sll_halen = ETH_ALEN;

    // ARP HEADER

    int help_sock = socketController.createIoctlSocket();

    arp_hdr.hardware_type = htons(1);
    arp_hdr.protocol_type = htons(0x0800);
    arp_hdr.hardware_len = 6;
    arp_hdr.protocol_len = 4;
    arp_hdr.opcode = htons(1);
    

    NetworkUtils::getMAC(&ifr, help_sock, this->src_mac);
    memcpy(arp_hdr.sender_mac, this->src_mac, 6);
    NetworkUtils::getIP(&ifr, help_sock, this->src_ip);
    memcpy(arp_hdr.sender_ip, this->src_ip, 4);

    
    memcpy(arp_hdr.target_mac, broadcast_mac, 6);
    memcpy(arp_hdr.target_ip, dst_ip, 4);

    std::cout << "target ip: " << dst_ip << std::endl;

    // EHTERNET HEADER

    memcpy(eth_hdr.dest, broadcast_mac, 6);
    memcpy(eth_hdr.src, src_mac, 6);
    eth_hdr.type = htons(ETH_P_ARP);  // ARP 
    
    memset(buffer, 0, ETH_FRAME_LEN);  // Заполняем буфер кадра
    memcpy(buffer, &eth_hdr, ETHER_HDR_LEN);
    memcpy(buffer + ETHER_HDR_LEN, &arp_hdr, ARP_HDR_LEN);

    if (sendto(this->socket, buffer, ETHER_HDR_LEN + ARP_HDR_LEN, 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll)) < 0) {
        perror("sendto() failed");
        exit(EXIT_FAILURE);
    }

    return SUCCESS_SENDED;
    

}

std::string ARPHandler::ListenToResponce(unsigned char* target_ip, long int timeout_ms) {
    while(1){
        memset(buffer, 0, BUFSIZE);
        std::cout << "Listening for ARP reply" << std::endl;

        struct timeval timeout;
        timeout.tv_sec = timeout_ms / 1000; 
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(this->socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        
        int length = recvfrom(this->socket, this->buffer, BUFSIZE, 0, NULL, NULL);

        std::cout << "Received packet" << std::endl;
        
        if (length < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                std::cout << "Timeout waiting for ARP reply..." << std::endl;
                return "";
            } else {
                perror("recvfrom() failed");
                break;
            }
        }
        
        ETH_HDR* eth_hdr = (ETH_HDR*)buffer;
        ARP_HDR* arp_hdr = (ARP_HDR*)(buffer + ETHER_HDR_LEN);

        if(ntohs(eth_hdr->type) != ETH_P_ARP) {
            std::cout << "Not an ARP packet" << std::endl;
            continue;
        }

        if(ntohs(arp_hdr->opcode) != 2){
            std::cout << "Not an ARP reply" << std::endl;
            continue;
        }

        if(memcmp(arp_hdr->target_ip, this->src_ip, 4) != 0 || memcmp(arp_hdr->target_mac, this->src_mac, 6) != 0){
            std::cout << "Not a response to our request" << std::endl;
            continue;
        }

        if (memcmp(arp_hdr->sender_ip, target_ip, 4) != 0) {
            std::cout << "Not a response to our request" << std::endl;
            continue;
        }
        std::cout << "-------------ARP reply received-------------" << std::endl;
        return NetworkUtils::macToString(arp_hdr->sender_mac);

    }

}


