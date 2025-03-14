#include "networkUtils.h"
#include "socketController.h"
#ifndef ARP_HANDLER_H
#define ARP_HANDLER_H


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

typedef struct eth_hdr{
    unsigned char dest[6];
    unsigned char src[6];
    unsigned short type;
} ETH_HDR;

class ARPHandler {
    private:
        int socket;
        unsigned char* buffer;
        const std::string iface;
        struct ifreq ifr;
        NetworkUtils networkUtils;
        SocketController socketController;

        unsigned char src_mac[6];  // Source MAC
        unsigned char src_ip[4];  // Source IP


    public:

        ARPHandler(const std::string& iface) : iface(iface) {
            socketController = SocketController();
            networkUtils = NetworkUtils();

            iface.copy(ifr.ifr_name, IFNAMSIZ);

            this->socket = socketController.createRawSocket();
            buffer = (unsigned char*)malloc(sizeof(unsigned char) * ETH_FRAME_LEN);
        }

        int SendARP(unsigned char* ipaddr);
        void SendICMP();
        void GetINF();

        std::string ListenToResponce(unsigned char* target_ip);

        ~ARPHandler() {
            close(this->socket);
            free(buffer);
        }

};

#endif // ARP_HANDLER_H