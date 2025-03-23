#ifndef ICMP_HANDLER_H
#define ICMP_HANDLER_H
#include "socketController.h"
#include "main.h"
#include "networkUtils.h"

typedef struct icmp_hdr {
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned short id;
    unsigned short seq;
} ICMP_HDR;


class ICMPHandler {

    int sock;
    struct ifreq ifr;
    const std::string& iface;
    unsigned char* buffer;
    SocketController socketController;
        
    public:

        ICMPHandler(std:: string iface) : iface(iface) {
            
            // this->sock = socketController.createRawSocket();

            iface.copy(ifr.ifr_name, IFNAMSIZ);
            buffer = (unsigned char*)malloc(sizeof(unsigned char) * ETH_FRAME_LEN);
        }

        ~ICMPHandler() {
            // this->sock = socketController.closeRawSocket();
        }

        int SendICMP(const unsigned char* target_ip, const unsigned char* target_mac);
        int SendICMPv6(const unsigned char* target_ip, const unsigned char* target_mac);
        bool ListenToResponceV6(const unsigned char* ipaddr, long int timeout_ms);
        bool ListenToResponce(const unsigned char* ipaddr, long int timeout_ms);
       

    private:  
        unsigned short checksum(void *b, int len);

        int icmp_hdr_id;

    

};


#endif // ICMP_HANDLER_H