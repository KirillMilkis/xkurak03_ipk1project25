
#include <linux/if_arp.h>


class Header {
    public:
        virtual void build() = 0;
        virtual ~Header() = default;
    };

    class ETHHeader : public Header {
        private:
            struct ethhdr eth_hdr;

            const unsigned char broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; 

        public:
            void build(int protocol, unsigned char dst_mac, struct ifreq ifr) override {
                std::cout << "Building ETH Header" << std::endl;

                switch(protocol){
                    case ETH_P_ARP:
                        this->eth_hdr.h_proto = htons(ETH_P_ARP);
                        break;
                    case ETH_P_IPV6:
                        this->eth_hdr.h_proto = htons(ETH_P_IPV6);
                        break;
                    default:
                        this->eth_hdr.h_proto = htons(ETH_P_IP);
                        break;
                }

                switch(protocol){
                    case ETH_P_ARP:
                        memset(this->eth_hdr.h_dest, broadcast_mac, 6); 
                        break;
                    case ETH_P_IPV6:
                        memset(this->eth_hdr.h_dest, 0xff, 6); 
                        break;
                    default:
                        memset(this->eth_hdr.h_dest, dest_mac, 6); 
                        break;
                }

                memcpy(this->eth_hdr.h_source, NetworkUtils::getMAC(&ifr), 6); 

            }

            struct ethhdr getHeader() {
                return this->eth_hdr;
            }


        };
    
    class ARPHeader : public Header {
        private:
            struct arphdr arp_hdr;
            const unsigned char broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
            unsigned char dst_ip[4];

        public:
            void build(unsigned char dst_ip, struct ifreq ifr) override {
                std::cout << "Building ARP Header" << std::endl;

                arp_hdr.hardware_type = htons(1);
                arp_hdr.protocol_type = htons(0x0800);
                arp_hdr.hardware_len = 6;
                arp_hdr.protocol_len = 4;
                arp_hdr.opcode = htons(1);

                memcpy(arp_hdr.sender_mac, NetworkUtils::getMAC(&ifr), 6);
                memcpy(arp_hdr.sender_ip, NetworkUtils::getIP(this->ifr.ifr_name, AF_INET), 4);
                memcpy(arp_hdr.target_mac, broadcast_mac, 6);
                memcpy(arp_hdr.target_ip, dst_ip, 4);


            }

            struct arphdr getHeader() {
                return this->arp_hdr;
            }
    };
    
    class IPHeader : public Header {

    private:
        struct iphdr ip_hdr;
        struct ifreq ifr;
        int protocol;

    public:
        void build(unsigned char* target_ip, struct ifreq ifr) override {
            std::cout << "Building IP Header" << std::endl;
            ip_hdr.ihl = 5;
            ip_hdr.version = 4;
            ip_hdr.tos = 0;
            ip_hdr.tot_len = htons(IP4_HDR_LEN + ICMP_HDR_LEN);
            ip_hdr.id = getpid();
            ip_hdr.frag_off = 0;
            ip_hdr.ttl = 255;
            ip_hdr.protocol = IPPROTO_ICMP;

            switch(protocol){
                case ETH_P_ARP:
                    ip_hdr.protocol = IPPROTO_ICMP;
                    ip_hdr.tot_len = htons(IP4_HDR_LEN + ARP_HDR_LEN);
                    break;
                case ETH_P_IPV6:
                    ip_hdr.protocol = IPPROTO_ICMPV6;
                    ip_hdr.tot_len = htons(IP4_HDR_LEN + ICMPV6_HDR_LEN);
                    break;
                default:
                    ip_hdr.protocol = IPPROTO_ICMP;
                    ip_hdr.tot_len = htons(IP4_HDR_LEN + ICMP_HDR_LEN);
                    break;
            }

            memcpy(&ip_hdr.saddr, NetworkUtils::getIP(this->ifr.ifr_name, AF_INET), 4);
            memcpy(&ip_hdr.daddr, target_ip, 4);
            ip_hdr.check = NetworkUtils::checksum(&ip_hdr, sizeof(ip_hdr));

        }

        struct iphdr getHeader() {
            return this->ip_hdr;
        }
    };
    
    class ICMPHeader : public Header {
    public:
        void build() override {
            std::cout << "Building ICMP Header" << std::endl;
        }
    };


    class ICMPHeader : public Header {
    private:
        struct icmp_hdr icmp_hdr;
        int icmp_hdr_id;

    public:
        void build() override {
            std::cout << "Building ICMP Header" << std::endl;

            icmp_hdr.type = 8;
            icmp_hdr.code = 0;
            this->icmp_hdr_id = getpid();
            icmp_hdr.id = this->icmp_hdr_id;
            icmp_hdr.seq = htons(1);
            icmp_hdr.checksum = ICMPHandler::checksum(&icmp_hdr, sizeof(icmp_hdr));
            


        }
    };
