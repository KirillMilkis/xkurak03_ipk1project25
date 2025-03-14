
#ifndef IPMANAGER_H
#define IPMANAGER_H

class IpManager {
    public: 
        IpManager(std::string subnet):
            subnet(subnet) {
                this->current_ip_int = 0;
                
            }

        unsigned char* getNextIp();
        int setSubnet(std::string subnet);
        unsigned char* getCurrentIp();


    private:
        // std::vector<std::string> subnet;
        std::string subnet;
        unsigned int current_ip_int;
        unsigned char* current_ip = NULL;
        unsigned int network_ip;
        unsigned int current_mask;
        int current_subnet;

        unsigned int ipToInt(std::string ip);
        unsigned char* intToIp(unsigned int ip_int);

};

#endif // IPMANAGER_H