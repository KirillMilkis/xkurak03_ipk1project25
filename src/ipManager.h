class IpManager {
    public: 
        IpManager(std::string subnet):
            subnet(subnet) {}

        char* getNextIp();
        int setSubnet(std::string subnet);



    private:
        // std::vector<std::string> subnet;
        std::string subnet;
        std::string current_ip;
        int current_subnet;

        unsigned int ipToInt(std::string ip);
        std::string intToIp(unsigned int ip);

};