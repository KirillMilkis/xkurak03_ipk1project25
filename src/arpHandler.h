#include "networkUtils.h"
#include "socketController.h"
#ifndef ARP_HANDLER_H
#define ARP_HANDLER_H

class ARPHandler {
    private:

    public:

        void SendARP(unsigned char* ipaddr);
        void SendICMP();
        void GetINF();

};

#endif // ARP_HANDLER_H