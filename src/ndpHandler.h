#include "networkUtils.h"
#include "socketController.h"

#ifndef NDP_HANDLER_H
#define NDP_HANDLER_H

#include "main.h"

#include <sys/socket.h>  // For socket(), bind(), etc.
#include <netinet/in.h>   // For sockaddr_in and related structures.
#include <net/if.h>       // For struct ifreq.
#include <arpa/inet.h>    // For IP address manipulation.
#include <linux/if_packet.h>  // For raw socket and ETH_P_ALL.

#define BUFSIZE 100
#define ETH_FRAME_LEN 1518
#define ARP_HDR_LEN 28
#define IP4_HDR_LEN 20
#define ETHER_HDR_LEN 14


class NDPHandler {
    private:
        int sock;
        unsigned char* buffer;
        const std::string iface;
        struct ifreq ifr;
        NetworkUtils networkUtils;
        SocketController socketController;

        unsigned char src_mac[6];  // Source MAC
        unsigned char src_ip[4];  // Source IP


    public:

        NDPHandler(const std::string& iface) : iface(iface) {
            socketController = SocketController();
            networkUtils = NetworkUtils();

            iface.copy(ifr.ifr_name, IFNAMSIZ);

            // this->socket = socketController.createRawSocket();
            buffer = (unsigned char*)malloc(sizeof(unsigned char) * ETH_FRAME_LEN);
        }

        int sendNDP(unsigned char* dst_ip6);
        int receiveNDP(const unsigned char* target_ip);
        

        std::string ListenToResponce(const unsigned char* target_ip, long int timeout_ms = 5000);

        ~NDPHandler() {
            close(this->sock);
            free(buffer);
        }

};

#endif // NDP_HANDLER_H
