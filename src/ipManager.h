
#ifndef IPMANAGER_H
#define IPMANAGER_H

class IpManager {
    public: 
        IpManager(std::string subnet):
            subnet(subnet) {}

        char* getNextIp();
        int setSubnet(std::string subnet);


    private:
        // std::vector<std::string> subnet;
        std::string subnet;
        unsigned int current_ip_int;
        std::string current_ip;
        unsigned int network_ip;
        unsigned int current_mask;
        int current_subnet;

        unsigned int ipToInt(std::string ip);
        char* intToIp(unsigned int ip);

};

#endif // IPMANAGER_H