#ifndef TRANSPORTHANDLER_H
#define TRANSPORTHANDLER_H


#define BUFSIZE 100
#define ETH_FRAME_LEN 1518
#define ARP_HDR_LEN 28
#define IP4_HDR_LEN 20
#define ETHER_HDR_LEN 14



class TransportHandler {
    private:
        int socket;
        unsigned char* buffer;
        const std::string iface;
        int protocol;
        struct ifreq ifr;
        NetworkUtils networkUtils;
        SocketController socketController;

        unsigned char src_mac[6];  // Source MAC
        unsigned char src_ip[4];  // Source IP


    public:

        TransportHandler(const std::string& iface, int protocol) : iface(iface), protocol(protocol) {
            // socketController = SocketController();
            networkUtils = NetworkUtils();

            iface.copy(ifr.ifr_name, IFNAMSIZ);
            
            buffer = (unsigned char*)malloc(sizeof(unsigned char) * ETH_FRAME_LEN);
        }

        int SendRequest(const unsigned char* ipaddr);

        std::string ListenToResponce(const unsigned char* target_ip, long int timeout_ms = 5000);

        ~TransportHandler() {
            close(this->socket);
            free(buffer);
        }

};


#endif // TRASPORTHANDLER_H