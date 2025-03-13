
#ifndef NETWORKUTILS_H
#define NETWORKUTILS_H

#include <iostream>
#include <array>

class NetworkUtils {
    private:

    public:
    unsigned char* getIP(struct ifreq* ifr, int sock, unsigned char* ipv4);
    unsigned char* getMAC(struct ifreq* ifr, int sock, unsigned char* mac);
};



#endif // NETWORKUTILS_H