#ifndef TRANSPORTHANDLER_H
#define TRANSPORTHANDLER_H

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <netinet/ip.h>
#include "networkUtils.h"
#include <sys/ioctl.h>
#include <net/if.h>

#include "headerBuilder.h"

// #define BUFSIZE 100
// #define ETH_FRAME_LEN 1518

#define SUCCESS_SENDED 3

#define SUCCESS_RECEIVED 4

class TransportHandler {
    private:
        int sock;
        unsigned char* buffer;
        const std::string iface;
        int protocol;
        struct ifreq ifr;
        NetworkUtils networkUtils;

        unsigned char src_mac[6];  // Source MAC
        unsigned char src_ip[4];  // Source IP

        unsigned char dst_mac[6];  // Destination MAC
        unsigned char dst_ip[4];  // Destination IP

        unsigned char dst_ip6[16];  // Destination IP


    public:

        TransportHandler(const std::string& iface, int protocol) : iface(iface), protocol(protocol) {

            memset(this->ifr.ifr_name, 0, IFNAMSIZ);

            memset(this->src_mac,0, 6);
            memset(this->src_ip, 0, 4);
            memset(this->dst_mac, 0, 6);
            memset(this->dst_ip, 0, 4);

            this->sock = -1;

            iface.copy(ifr.ifr_name, IFNAMSIZ);

            buffer = (unsigned char*)malloc(sizeof(unsigned char) * ETH_FRAME_LEN);
            if(buffer == NULL) {
                perror("malloc() failed");
                exit(EXIT_FAILURE);
            }

        }

        int SendRequest(const unsigned char* ipaddr, const unsigned char* dst_mac);

        int ListenToResponce(long int timeout_ms);

        bool testArpResponse(const unsigned char* buffer);

        bool testICMPResponse(const unsigned char* buffer);

        bool testNDPResponse(const unsigned char* buffer);

        bool testICMPv6Response(const unsigned char* buffer);

        std::string GetDestMAC();

        ~TransportHandler() {
            if(this->buffer != NULL) {
                free(this->buffer);
            }
            if(this->sock > 0) {
                close(this->sock);
            }
        }

};


#endif // TRASPORTHANDLER_H