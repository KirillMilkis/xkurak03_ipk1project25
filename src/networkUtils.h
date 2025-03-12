
#ifndef NETWORKUTILS_H
#define NETWORKUTILS_H

#include <iostream>

class NetworkUtils {
    public:
    static unsigned char* getMAC(struct ifreq* ifr, int sock);
    static unsigned char* getIP(struct ifreq* ifr, int sock);
};



#endif // NETWORKUTILS_H