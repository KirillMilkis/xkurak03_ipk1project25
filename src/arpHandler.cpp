
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

int ARPHandler::SendARP(unsigned char* dst_ip) {

    // Function to send ARP packets
    std::cout << "Sending ARP packet" << std::endl;

    ETH_HDR eth_hdr;
    ARP_HDR arp_hdr;
    unsigned char broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // Broadcast MAC
    unsigned char src_mac[6];  // Source MAC
    unsigned char src_ip[4];  // Source IP
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

    int sock = socketController.createIoctlSocket();

    arp_hdr.hardware_type = htons(1);
    arp_hdr.protocol_type = htons(0x0800);
    arp_hdr.hardware_len = 6;
    arp_hdr.protocol_len = 4;
    arp_hdr.opcode = htons(1);
    

    NetworkUtils::getMAC(&ifr, sock, src_mac);
    memcpy(arp_hdr.sender_mac, src_mac, 6);
    NetworkUtils::getIP(&ifr, sock, src_ip);
    memcpy(arp_hdr.sender_ip, src_ip, 4);

    
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

void ARPHandler::ListenToResponce() {
    while(1){
        int length = recvfrom(this->socket, this->buffer, BUFSIZE, 0, NULL, NULL);
        if (length < 0) {
            perror("recvfrom() failed");
            exit(EXIT_FAILURE);
        } else{

            std::cout << "Received packet" << std::endl;

            // Parse the received packet

        }
    }

}


