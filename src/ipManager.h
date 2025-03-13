
#ifndef IPMANAGER_H
#define IPMANAGER_H

class IpManager {
    public: 
        IpManager(std::string subnet):
            subnet(subnet) {
                this->current_ip_int = 0;
                // this->current_ip = (unsigned char*)malloc(sizeof(unsigned char) * 4);
            }

        unsigned char* getNextIp(unsigned char* result_ip);
        int setSubnet(std::string subnet);


    private:
        // std::vector<std::string> subnet;
        std::string subnet;
        unsigned int current_ip_int;
        unsigned char* current_ip;
        unsigned int network_ip;
        unsigned int current_mask;
        int current_subnet;

        unsigned int ipToInt(std::string ip);
        unsigned char* intToIp(unsigned int ip_int, unsigned char* result);

};

#endif // IPMANAGER_H