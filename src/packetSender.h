#include "networkUtils.h"
#include "socketController.h"
#ifndef PACKETSENDER_H
#define PACKETSENDER_H

class PacketSender {
    private:

    public:

        void SendARP(char* ipaddr);
        void SendICMP();
        void GetINF();

};

#endif // PACKETSENDER_H