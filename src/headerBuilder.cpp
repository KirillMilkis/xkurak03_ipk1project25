

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


#include <netinet/ip6.h>
// 
#include <netinet/icmp6.h>


#define IP4_HDR_LEN 20
#define ETHER_HDR_LEN 14
#define ICMP_HDR_LEN 8
#define ARP_HDR_LEN 28
#define ICMP6_HDR_LEN 32 
#define IP6_HDR_LEN 40

#define ARP 1
#define ICMP 2
#define ICMPv6 4
#define NDP 3

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


class HeaderBuilder {

        private:
            struct ethhdr eth_hdr;
            struct iphdr ip_hdr;
            struct ifreq ifr;
            int protocol;
            ARP_HDR arp_hdr;    
            struct icmp_hdr icmp_hdr;
            int icmp_hdr_id;
            struct ip6_hdr ip6_hdr;
            struct icmp6_hdr icmpv6_hdr;
            struct nd_neighbor_solicit ns;

            const unsigned char broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; 

        public:
            void buildETH(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr) {
          
                memset(&this->eth_hdr, 0, sizeof(this->eth_hdr));

                switch(protocol){
                    case ARP:
                        this->eth_hdr.h_proto = htons(ETH_P_ARP);
                        break;
                    case ICMPv6:
                    case NDP:
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
                    case NDP:
                        memcpy(this->eth_hdr.h_dest, "\x33\x33\xff\x00\x00\x01", 6); // IPv6 multicast для NS
                        break;
                    case ICMP:
                    case ICMPv6:
                        memcpy(this->eth_hdr.h_dest, dst_mac, 6); 
                        break;
                    default:
                        memcpy(this->eth_hdr.h_dest, dst_mac, 6); 
                        break;
                }
              

                memcpy(this->eth_hdr.h_source, NetworkUtils::getMAC(&ifr), 6); 


            }

            const struct ethhdr* getETHHeader() {
                return &this->eth_hdr;
            }

    
  
            void buildARP(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr) {
                // std::cout << "Building ARP Header" << std::endl;
                memset(&this->arp_hdr, 0, sizeof(this->arp_hdr));
                this->arp_hdr.ar_hrd = htons(ARPHRD_ETHER);  
                this->arp_hdr.ar_pro = htons(ETH_P_IP);       
                this->arp_hdr.ar_hln = 6;                     
                this->arp_hdr.ar_pln = 4;                     
                this->arp_hdr.ar_op = htons(ARPOP_REQUEST);   
               
                memcpy(this->arp_hdr.ar_sha, NetworkUtils::getMAC(&ifr), 6);  
        
                memcpy(this->arp_hdr.ar_sip, NetworkUtils::getIP(ifr.ifr_name, AF_INET), 4); 
            
                memcpy(this->arp_hdr.ar_tha, broadcast_mac, 6); 
            
                memcpy(this->arp_hdr.ar_tip, dst_ip, 4); 


            }

            const struct arphdr* getARPHeader() {
                return reinterpret_cast<const struct arphdr*>(&this->arp_hdr); // Приведение типа
            }

 
            void buildIP(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr) {
            // std::cout << "Building IP Header" << std::endl;
            this->ip_hdr.ihl = 5;
            this->ip_hdr.version = 4;
            this->ip_hdr.tos = 0;
            this->ip_hdr.tot_len = htons(IP4_HDR_LEN + ICMP_HDR_LEN);
            this->ip_hdr.id = getpid();
            this->ip_hdr.frag_off = 0;
            this->ip_hdr.ttl = 255;
            this->ip_hdr.protocol = IPPROTO_ICMP;

            switch(protocol){
                case ICMP:
                    this->ip_hdr.protocol = IPPROTO_ICMP;
                    this->ip_hdr.tot_len = htons(IP4_HDR_LEN + ICMP_HDR_LEN);
                    break;
                case ICMPv6:
                    this->ip_hdr.protocol = IPPROTO_ICMPV6;
                    this->ip_hdr.tot_len = htons(IP4_HDR_LEN + ICMP6_HDR_LEN);
                    break;
                default:
                    this->ip_hdr.protocol = IPPROTO_ICMP;
                    this->ip_hdr.tot_len = htons(IP4_HDR_LEN + ICMP_HDR_LEN);
                    break;
            }

            memcpy(&this->ip_hdr.saddr, NetworkUtils::getIP(this->ifr.ifr_name, AF_INET), 4);
            memcpy(&this->ip_hdr.daddr, dst_ip, 4);
            this->ip_hdr.check = NetworkUtils::checksum(&this->ip_hdr, sizeof(this->ip_hdr));

        }

        const struct iphdr* getIPHeader() {
            return &this->ip_hdr;
        }
    

        void buildICMP(int protocol, const unsigned char* dst_ip,const  unsigned char* dst_mac, struct ifreq ifr) {
            // std::cout << "Building ICMP Header" << std::endl;

            memset(&icmp_hdr, 0, sizeof(icmp_hdr));
            icmp_hdr.type = 8;
            icmp_hdr.code = 0;
            this->icmp_hdr_id = getpid();
            icmp_hdr.id = this->icmp_hdr_id;
            icmp_hdr.seq = htons(1);
            icmp_hdr.checksum = NetworkUtils::checksum(&icmp_hdr, sizeof(icmp_hdr));

        }

        const struct icmp_hdr* getICMPHeader() {
            return &this->icmp_hdr;
        }
 
        void buildIP6(int protocol, const unsigned char* dst_ip,const  unsigned char* dst_mac, struct ifreq ifr) {

            this->ip6_hdr.ip6_flow = htonl((6 << 28) | (0 << 20) | 0);
            this->ip6_hdr.ip6_plen = htons(24); 
            this->ip6_hdr.ip6_nxt = IPPROTO_ICMPV6; 
            this->ip6_hdr.ip6_hlim = 255; 

            memcpy(&this->ip6_hdr.ip6_src, NetworkUtils::getIP(ifr.ifr_name, AF_INET6), 16);
            // inet_pton(AF_INET6, NetworkUtils::getIP(this->ifr.ifr_name, AF_INET6), &ip6_hdr.ip6_src); 
            memcpy(&this->ip6_hdr.ip6_dst, dst_ip, 16);

           
        }

        const struct ip6_hdr* getIP6Header() {
            return &this->ip6_hdr;
        }

  
      
        void buildNS(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr) {

            memset(&ns, 0, sizeof(ns));
            this->ns.nd_ns_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;
            this->ns.nd_ns_hdr.icmp6_code = 0;
            this->ns.nd_ns_hdr.icmp6_cksum = 0;
            memcpy(&ns.nd_ns_target, dst_ip, 16); 

            this->ip6_hdr.ip6_plen = htons(sizeof(ns));

            struct {
                struct in6_addr src;
                struct in6_addr dst;
                uint32_t length;
                uint8_t zero[3];
                uint8_t next_header;
            } pseudo_header;
        
            memcpy(&pseudo_header.src, &this->ip6_hdr.ip6_src, sizeof(struct in6_addr));
            memcpy(&pseudo_header.dst, &this->ip6_hdr.ip6_dst, sizeof(struct in6_addr));
            pseudo_header.length = htonl(sizeof(ns));
            memset(pseudo_header.zero, 0, sizeof(pseudo_header.zero));
            pseudo_header.next_header = IPPROTO_ICMPV6;
        
        
            uint8_t temp_buffer[sizeof(pseudo_header) + sizeof(this->ns)];
            memcpy(temp_buffer, &pseudo_header, sizeof(pseudo_header));
            memcpy(temp_buffer + sizeof(pseudo_header), &ns, sizeof(this->ns));
        
          
            ns.nd_ns_hdr.icmp6_cksum = NetworkUtils::checksum(temp_buffer, sizeof(temp_buffer));
        

        }

        const struct nd_neighbor_solicit* getNSHeader() {
            return &this->ns;
        }



        void buildICMP6(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr) {

            

            // memset(&icmpv6_hdr, 0, sizeof(icmpv6_hdr));
            // this->icmpv6_hdr.icmp6_type = 128; // Echo Request
            // this->icmpv6_hdr.icmp6_code = 0;
            // this->icmp_hdr_id = getpid();
            // this->icmpv6_hdr.icmp6_dataun.icmp6_un_data16[0] = htons(this->icmp_hdr_id);
            // this->icmpv6_hdr.icmp6_dataun.icmp6_un_data16[1] = htons(1);
            // this->icmpv6_hdr.icmp6_cksum = 0; // Checksum will be calculated later

            // // Calculate ICMPv6 checksum
            // struct {
            //     struct in6_addr src;
            //     struct in6_addr dst;
            //     uint32_t length;
            //     uint8_t zero[3];
            //     uint8_t next_header;
            // } pseudo_header;

            // memset(&pseudo_header, 0, sizeof(pseudo_header));
            // memcpy(&pseudo_header.src, &this->ip6_hdr.ip6_src, sizeof(struct in6_addr));
            // memcpy(&pseudo_header.dst, &this->ip6_hdr.ip6_dst, sizeof(struct in6_addr));
            // pseudo_header.length = htonl(sizeof(this->icmpv6_hdr));
            // pseudo_header.next_header = IPPROTO_ICMPV6;

            // unsigned char checksum_buffer[sizeof(pseudo_header) + sizeof(this->icmpv6_hdr)];
            // memcpy(checksum_buffer, &pseudo_header, sizeof(pseudo_header));
            // memcpy(checksum_buffer + sizeof(pseudo_header), &this->icmpv6_hdr, sizeof(this->icmpv6_hdr));

            // icmpv6_hdr.icmp6_cksum = NetworkUtils::checksum(checksum_buffer, sizeof(checksum_buffer));

            memset(&icmpv6_hdr, 0, sizeof(icmpv6_hdr));
    
            // Заполняем ICMPv6 заголовок
            icmpv6_hdr.icmp6_type = 128; // Echo Request
            icmpv6_hdr.icmp6_code = 0;
            icmpv6_hdr.icmp6_cksum = 0; // Считаем позже
            icmpv6_hdr.icmp6_dataun.icmp6_un_data16[0] = htons(getpid()); // ID процесса
            icmpv6_hdr.icmp6_dataun.icmp6_un_data16[1] = htons(1); // Sequence number
        
            // IPv6 заголовок
            this->ip6_hdr.ip6_plen = htons(sizeof(icmpv6_hdr));
   
            struct {
                struct in6_addr src;
                struct in6_addr dst;
                uint32_t length;
                uint8_t zero[3];
                uint8_t next_header;
            } pseudo_header;
        
            memset(&pseudo_header, 0, sizeof(pseudo_header));
            memcpy(&pseudo_header.src, &this->ip6_hdr.ip6_src, sizeof(struct in6_addr));
            memcpy(&pseudo_header.dst, &this->ip6_hdr.ip6_dst, sizeof(struct in6_addr));
            pseudo_header.length = htonl(sizeof(icmpv6_hdr));
            pseudo_header.next_header = IPPROTO_ICMPV6;
        
            
            uint8_t temp_buffer[sizeof(pseudo_header) + sizeof(icmpv6_hdr)];
            memcpy(temp_buffer, &pseudo_header, sizeof(pseudo_header));
            memcpy(temp_buffer + sizeof(pseudo_header), &icmpv6_hdr, sizeof(icmpv6_hdr));
        
            icmpv6_hdr.icmp6_cksum = NetworkUtils::checksum((uint16_t*)temp_buffer, sizeof(temp_buffer));
        }

        const struct icmp6_hdr* getICMP6Header() {
            return &this->icmpv6_hdr;
        }



    
    };


