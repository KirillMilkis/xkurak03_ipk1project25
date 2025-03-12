
#include <iostream>
#include <string>
#include <vector>
#include <cstdio>
#include <sys/ioctl.h>
#include <net/if.h>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>

#include "packetSender.h"

#define BUFSIZE 100

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

void PacketSender::SendARP(char* ipaddr) {
    // Function to send ARP packets
    std::cout << "Sending ARP packet" << std::endl;



    NetworkUtils networkUtils;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sock < 0){
        perror("Socket error");
        exit(1);
    }

    struct ifreq ifr;

    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", "enp0s3");

    unsigned char* buffer;
    buffer = (unsigned char*)malloc(sizeof(unsigned char) * BUFSIZE);
    memset(buffer, 0, BUFSIZE);

    // Create a raw socket

    ARP_HDR* packet_header = (ARP_HDR*)malloc(sizeof(ARP_HDR));
    packet_header->hardware_type = htons(1);
    packet_header->protocol_type = htons(0x0800);
    packet_header->hardware_len = 6;
    packet_header->protocol_len = 4;
    packet_header->opcode = htons(1);
    // packet_header->sender_mac = networkUtils.getMAC(&ifr, sock);
    // packet_header->sender_ip = networkUtils.getIP(&ifr, sock);
    unsigned char broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(packet_header->target_mac, broadcast_mac, 6);
    // memcpy(packet_header->target_ip, ipaddr);

    close(sock);
    
    // this->GetINF();
    
//     libnet_t *l;  /* the libnet context */
//   char errbuf[LIBNET_ERRBUF_SIZE], target_ip_addr_str[16];
//   u_int32_t target_ip_addr, src_ip_addr;
//   u_int8_t mac_broadcast_addr[6] = {0xff, 0xff, 0xff, 0xff,\
//           0xff, 0xff},
//      mac_zero_addr[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
//   struct libnet_ether_addr *src_mac_addr;
//   int bytes_written;

//   l = libnet_init(LIBNET_LINK, NULL, errbuf);
//   if ( l == NULL ) {
//     fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
//     exit(EXIT_FAILURE);
//   }

//   /* Getting our own MAC and IP addresses */

//   src_ip_addr = libnet_get_ipaddr4(l);
//   if ( src_ip_addr == -1 ) {
//     fprintf(stderr, "Couldn't get own IP address: %s\n",\
//                     libnet_geterror(l));
//     libnet_destroy(l);
//     exit(EXIT_FAILURE);
//   }

//   src_mac_addr = libnet_get_hwaddr(l);
//   if ( src_mac_addr == NULL ) {
//     fprintf(stderr, "Couldn't get own IP address: %s\n",\
//                     libnet_geterror(l));
//     libnet_destroy(l);
//     exit(EXIT_FAILURE);
//   }

//   /* Getting target IP address */

//   printf("Target IP address: ");
//   scanf("%15s",target_ip_addr_str);

//   target_ip_addr = libnet_name2addr4(l, target_ip_addr_str,\
//       LIBNET_DONT_RESOLVE);

//   if ( target_ip_addr == -1 ) {
//     fprintf(stderr, "Error converting IP address.\n");
//     libnet_destroy(l);
//     exit(EXIT_FAILURE);
//   }

//   /* Building ARP header */

//   if ( libnet_autobuild_arp (ARPOP_REQUEST,\
//       src_mac_addr->ether_addr_octet,\
//       (u_int8_t*)(&src_ip_addr), mac_zero_addr,\
//       (u_int8_t*)(&target_ip_addr), l) == -1)
//   {
//     fprintf(stderr, "Error building ARP header: %s\n",\
//         libnet_geterror(l));
//     libnet_destroy(l);
//     exit(EXIT_FAILURE);
//   }

//   /* Building Ethernet header */

//   if ( libnet_autobuild_ethernet (mac_broadcast_addr,\
//                           ETHERTYPE_ARP, l) == -1 )
//   {
//     fprintf(stderr, "Error building Ethernet header: %s\n",\
//         libnet_geterror(l));
//     libnet_destroy(l);
//     exit(EXIT_FAILURE);
//   }

//   /* Writing packet */

//   bytes_written = libnet_write(l);
//   if ( bytes_written != -1 )
//     printf("%d bytes written.\n", bytes_written);
//   else
//     fprintf(stderr, "Error writing packet: %s\n",\
//         libnet_geterror(l));

//   libnet_destroy(l);
//   return 0;
}