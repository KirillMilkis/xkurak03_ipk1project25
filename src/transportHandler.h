#ifndef TRANSPORTHANDLER_H
#define TRANSPORTHANDLER_H


#define BUFSIZE 100
#define ETH_FRAME_LEN 1518
#define ARP_HDR_LEN 28
#define IP4_HDR_LEN 20
#define ETHER_HDR_LEN 14

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <netinet/ip.h>
#include "networkUtils.h"
#include "socketController.h"


#define ARP 1
#define ICMP 2
#define ICMPv6 3
#define NDP 4


// typedef struct ARP_Header {
//     uint16_t ar_hrd;   // Hardware type (Ethernet = 1)
//     uint16_t ar_pro;   // Protocol type (IPv4 = 0x0800)
//     uint8_t ar_hln;    // Hardware address length (MAC = 6)
//     uint8_t ar_pln;    // Protocol address length (IPv4 = 4)
//     uint16_t ar_op;    // Operation (1 = request, 2 = reply)

//     uint8_t ar_sha[6]; // Sender MAC address
//     uint8_t ar_sip[4]; // Sender IP address
//     uint8_t ar_tha[6]; // Target MAC address
//     uint8_t ar_tip[4]; // Target IP address
// } ARP_HDR;

#define SUCCESS_RECEIVED 4

class TransportHandler {
    private:
        int sock;
        unsigned char* buffer;
        const std::string iface;
        int protocol;
        struct ifreq ifr;
        NetworkUtils networkUtils;
        SocketController socketController;

        unsigned char src_mac[6];  // Source MAC
        unsigned char src_ip[4];  // Source IP

        unsigned char dst_mac[6];  // Destination MAC
        unsigned char dst_ip[4];  // Destination IP

        unsigned char dst_ip6[4];  // Destination IP


    public:

        TransportHandler(const std::string& iface, int protocol) : iface(iface), protocol(protocol) {
            // socketController = SocketController();
            networkUtils = NetworkUtils();

            iface.copy(ifr.ifr_name, IFNAMSIZ);

            buffer = (unsigned char*)malloc(sizeof(unsigned char) * ETH_FRAME_LEN);

        }

        int SendRequest(const unsigned char* ipaddr, const unsigned char* dst_mac);

        int ListenToResponce(const unsigned char* target_ip, long int timeout_ms);

        bool testArpResponse(const unsigned char* buffer);

        bool testICMPResponse(const unsigned char* buffer);

        bool testNDPResponse(const unsigned char* buffer);

        std::string GetDestMAC();

        ~TransportHandler() {
            close(this->sock);
            free(buffer);
        }

};


#endif // TRASPORTHANDLER_H