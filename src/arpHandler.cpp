
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

#include "packetSender.h"

#define BUFSIZE 100
#define ETH_FRAME_LEN 1518
#define ARP_HDR_LEN 28
#define IP4_HDR_LEN 20
#define ETHER_HDR_LEN 14


typedef struct arp_hdr {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[6];
    unsigned char sender_ip[4];
    unsigned char target_mac[6];
    unsigned char target_ip[4];
} ARP_HDR;

void PacketSender::SendARP(unsigned char* ipaddr) {

    printf("ipaddr: %s\n", ipaddr);
    // Function to send ARP packets
    std::cout << "Sending ARP packet" << std::endl;

    NetworkUtils networkUtils;
    SocketController socketController;

    uint8_t ether_hdr[ETHER_HDR_LEN];
    struct sockaddr_ll sa;
    struct ifreq ifr;

    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", "enp0s3");

    unsigned char* buffer;
    buffer = (unsigned char*)malloc(sizeof(unsigned char) * ETH_FRAME_LEN);
    memset(buffer, 0, ETH_FRAME_LEN);

    // Get the index of the network device

    memset(&sa, 0, sizeof(struct sockaddr_ll));
    sa.sll_protocol = htons(ETH_P_ALL);  
    if ((sa.sll_ifindex = if_nametoindex (ifr.ifr_name)) == 0) {
        perror ("if_nametoindex() failed to obtain interface index");
        exit (EXIT_FAILURE);
      }
    sa.sll_halen = ETH_ALEN;

    // EHTERNET HEADER

    uint8_t ethDest[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // Broadcaset MAC
    memcpy(ether_hdr, ethDest, 6);
    uint8_t ethSource[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}; // MAC
    memcpy(ether_hdr + 6, ethSource, 6);
    uint16_t ethType = htons(ETH_P_ARP);  // ARP 
    memcpy(ether_hdr + 12, &ethType, sizeof(ethType));

    // ARP HEADER

    int sock = socketController.createIoctlSocket();

    ARP_HDR* arp_hdr = (ARP_HDR*)malloc(sizeof(ARP_HDR));
    arp_hdr->hardware_type = htons(1);
    arp_hdr->protocol_type = htons(0x0800);
    arp_hdr->hardware_len = 6;
    arp_hdr->protocol_len = 4;
    arp_hdr->opcode = htons(1);

    networkUtils.getMAC(&ifr, sock, arp_hdr->sender_mac);
    networkUtils.getIP(&ifr, sock, arp_hdr->sender_ip);
    
    unsigned char broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(arp_hdr->target_mac, broadcast_mac, 6);
    memcpy(arp_hdr->target_ip, ipaddr, 4);

    std::cout << "target ip: " << ipaddr << std::endl;

    socketController.createIoctlSocket();

    sock = socketController.createRawSocket();


    memset(buffer, 0, ETH_FRAME_LEN);  // Заполняем буфер кадра
    memcpy(buffer, ether_hdr, ETHER_HDR_LEN);
    memcpy(buffer + ETHER_HDR_LEN, arp_hdr, ARP_HDR_LEN);

    if (sendto(sock, buffer, ETHER_HDR_LEN + ARP_HDR_LEN, 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll)) < 0) {
        perror("sendto() failed");
        exit(EXIT_FAILURE);
    }

    socketController.closeIoctlSocket();
    

}