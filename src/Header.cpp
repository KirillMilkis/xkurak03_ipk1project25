

#include <iostream>
#include <string>
#include <array>
#include <vector>
#include <cstdio>
#include <sys/ioctl.h>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h> // for iphdr
#include <unistd.h>

#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>

#include <net/if.h> // for struct ifreq

#include "networkUtils.h"


#define IP4_HDR_LEN 20
#define ETHER_HDR_LEN 14
#define ICMP_HDR_LEN 8
#define ARP_HDR_LEN 28
#define ICMPV6_HDR_LEN 8
#define IP6_HDR_LEN 40

#define ARP 1
#define ICMP 2
#define ICMPv6 3
#define NDP 4

typedef struct ARP_Header {
    uint16_t ar_hrd;   // Hardware type (Ethernet = 1)
    uint16_t ar_pro;   // Protocol type (IPv4 = 0x0800)
    uint8_t ar_hln;    // Hardware address length (MAC = 6)
    uint8_t ar_pln;    // Protocol address length (IPv4 = 4)
    uint16_t ar_op;    // Operation (1 = request, 2 = reply)

    uint8_t ar_sha[6]; // Sender MAC address
    uint8_t ar_sip[4]; // Sender IP address
    uint8_t ar_tha[6]; // Target MAC address
    uint8_t ar_tip[4]; // Target IP address
} ARP_HDR;


typedef struct icmp_hdr {
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned short id;
    unsigned short seq;
} ICMP_HDR;


class Header {
    public:
        virtual void build(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr) = 0;
        virtual ~Header() = default;
    };

    class ETHHeader : public Header {
        private:
            struct ethhdr eth_hdr;

            const unsigned char broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; 

        public:
            void build(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr) override {
                // std::cout << "Building ETH Header" << std::endl;

                switch(protocol){
                    case ARP:
                        this->eth_hdr.h_proto = htons(ETH_P_ARP);
                        break;
                    case ICMPv6:
                        this->eth_hdr.h_proto = htons(ETH_P_IPV6);
                        break;
                    default:
                        this->eth_hdr.h_proto = htons(ETH_P_IP);
                        break;
                }

                switch(protocol){
                    case ARP:
                        memcpy(this->eth_hdr.h_dest, broadcast_mac, 6); 
                        break;
                    case ICMPv6:
                        memcpy(this->eth_hdr.h_dest, dst_mac, 6); 
                        break;
                    default:
                        memcpy(this->eth_hdr.h_dest, dst_mac, 6); 
                        break;
                }

                memcpy(this->eth_hdr.h_source, NetworkUtils::getMAC(&ifr), 6); 

            }

            const struct ethhdr* getHeader() {
                return &this->eth_hdr;
            }


        };


    
    class ARPHeader : public Header {
        private:
            ARP_HDR arp_hdr;
            const unsigned char broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
            unsigned char dst_ip[4];

        public:
            void build(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr) override {
                // std::cout << "Building ARP Header" << std::endl;

                arp_hdr.ar_hrd = htons(ARPHRD_ETHER);  
                arp_hdr.ar_pro = htons(ETH_P_IP);       
                arp_hdr.ar_hln = 6;                     
                arp_hdr.ar_pln = 4;                     
                arp_hdr.ar_op = htons(ARPOP_REQUEST);   
               
                memcpy(arp_hdr.ar_sha, NetworkUtils::getMAC(&ifr), 6);  
        
                memcpy(arp_hdr.ar_sip, NetworkUtils::getIP(ifr.ifr_name, AF_INET), 4); 
            
                memcpy(arp_hdr.ar_tha, broadcast_mac, 6); 
            
                memcpy(arp_hdr.ar_tip, dst_ip, 4); 


            }

            const struct arphdr* getHeader() {
                return reinterpret_cast<const struct arphdr*>(&this->arp_hdr); // Приведение типа
            }
    };

  
    class IPHeader : public Header {

    private:
        struct iphdr ip_hdr;
        struct ifreq ifr;
        int protocol;

    public:
        void build(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr) override {
            // std::cout << "Building IP Header" << std::endl;
            ip_hdr.ihl = 5;
            ip_hdr.version = 4;
            ip_hdr.tos = 0;
            ip_hdr.tot_len = htons(IP4_HDR_LEN + ICMP_HDR_LEN);
            ip_hdr.id = getpid();
            ip_hdr.frag_off = 0;
            ip_hdr.ttl = 255;
            ip_hdr.protocol = IPPROTO_ICMP;

            switch(protocol){
                case ICMP:
                    ip_hdr.protocol = IPPROTO_ICMP;
                    ip_hdr.tot_len = htons(IP4_HDR_LEN + ICMP_HDR_LEN);
                    break;
                case ICMPv6:
                    ip_hdr.protocol = IPPROTO_ICMPV6;
                    ip_hdr.tot_len = htons(IP4_HDR_LEN + ICMPV6_HDR_LEN);
                    break;
                default:
                    ip_hdr.protocol = IPPROTO_ICMP;
                    ip_hdr.tot_len = htons(IP4_HDR_LEN + ICMP_HDR_LEN);
                    break;
            }

            memcpy(&ip_hdr.saddr, NetworkUtils::getIP(this->ifr.ifr_name, AF_INET), 4);
            memcpy(&ip_hdr.daddr, dst_ip, 4);
            ip_hdr.check = NetworkUtils::checksum(&ip_hdr, sizeof(ip_hdr));

        }

        const struct iphdr* getHeader() {
            return &this->ip_hdr;
        }
    };
    

    class ICMPHeader : public Header {
    private:
        struct icmp_hdr icmp_hdr;
        int icmp_hdr_id;

    public:
        void build(int protocol, const unsigned char* dst_ip,const  unsigned char* dst_mac, struct ifreq ifr) override {
            // std::cout << "Building ICMP Header" << std::endl;

            memset(&icmp_hdr, 0, sizeof(icmp_hdr));
            icmp_hdr.type = 8;
            icmp_hdr.code = 0;
            this->icmp_hdr_id = getpid();
            icmp_hdr.id = this->icmp_hdr_id;
            icmp_hdr.seq = htons(1);
            icmp_hdr.checksum = NetworkUtils::checksum(&icmp_hdr, sizeof(icmp_hdr));

        }

        const struct icmp_hdr* getHeader() {
            return &this->icmp_hdr;
        }
    };
