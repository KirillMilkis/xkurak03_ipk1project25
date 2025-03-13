#ifndef SOCKETCONTROLLER_H
#define SOCKETCONTROLLER_H


#include <sys/types.h>      // (`socklen_t`)
#include <sys/socket.h>     // (`socket`, `bind`, `connect`, `send`, `recv` и т. д.)
#include <netinet/in.h>     //  (`sockaddr_in`)
#include <arpa/inet.h>      // (`inet_pton`, `inet_ntop`)
#include <unistd.h>         // `close()` 
#include <netdb.h>          // DNS (`getaddrinfo`, `gethostbyname`)
#include <cstring>          // `memset()`, `memcpy()`
#include <iostream>     

#include <net/if.h>         // `struct ifreq`, `SIOCGIFADDR`
#include <linux/if_ether.h> // `ETH_P_ALL`, `ETH_P_IP`, `ETH_P_ARP`
#include <linux/if_packet.h>// `sockaddr_ll` L2
#include <sys/ioctl.h>      // `ioctl()`

class SocketController {
    public:
        int ioctl_socket;
        int raw_socket;
        
        int createRawSocket();
        int createIoctlSocket();
        int getRawSocket();
        int getIoctlSocket();
        void closeRawSocket();
        void closeIoctlSocket();


};

#endif // SOCKETCONTROLLER_H