#include "networkUtils.h"
#include "socketController.h"
#ifndef ARP_HANDLER_H
#define ARP_HANDLER_H

class ARPHandler {
    private:
        int socket;
        unsigned char* buffer;
        const std::string iface;
        NetworkUtils networkUtils;
        SocketController socketController;


    public:

        ARPHandler(int socket, const std::string& iface) : iface(iface) {
            socketController = SocketController();
            networkUtils = NetworkUtils();

            this->socket = socketController.createRawSocket();
            buffer = (unsigned char*)malloc(sizeof(unsigned char) * ETH_FRAME_LEN);
        }

        void SendARP(unsigned char* ipaddr);
        void SendICMP();
        void GetINF();

        ~ARPHandler() {
            close(this->socket);
            free(buffer);
        }

};

#endif // ARP_HANDLER_H