
#ifndef NETWORKUTILS_H
#define NETWORKUTILS_H

#include <iostream>
#include <array>

#include <unistd.h>  

class NetworkUtils {
    private:
        static unsigned char* ip_addrv4;
        static unsigned char* ip_addrv6;
        static unsigned char* mac_addr;

    public:
    static unsigned char* getIP(const char* iface, int family);
    static unsigned char* getMAC(struct ifreq* ifr);

    static std::string macToString(unsigned char* mac);
    static std::string ipToString(const unsigned char* ip);


};



#endif // NETWORKUTILS_H