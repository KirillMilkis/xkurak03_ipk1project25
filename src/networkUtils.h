
#ifndef NETWORKUTILS_H
#define NETWORKUTILS_H

#include <iostream>
#include <array>

class NetworkUtils {
    private:

    public:
    static unsigned char* getIP(struct ifreq* ifr, int sock, unsigned char* ipv4);
    static unsigned char* getMAC(struct ifreq* ifr, int sock, unsigned char* mac);

    static std::string macToString(unsigned char* mac);
    static std::string ipToString(const unsigned char* ip);
};



#endif // NETWORKUTILS_H