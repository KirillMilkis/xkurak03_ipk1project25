

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
            struct icmp6_hdr icmp6_hdr;

            const unsigned char broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; 

        public:
            void buildETH(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr) {
          

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
                    case NDP:
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

            const struct ethhdr* getETHHeader() {
                return &this->eth_hdr;
            }

    
  
            void buildARP(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr) {
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

            const struct arphdr* getARPHeader() {
                return reinterpret_cast<const struct arphdr*>(&this->arp_hdr); // Приведение типа
            }

 
            void buildIP(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr) {
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
                    ip_hdr.tot_len = htons(IP4_HDR_LEN + ICMP6_HDR_LEN);
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

            ip6_hdr.ip6_flow = htonl((6 << 28) | (0 << 20) | 0);
            ip6_hdr.ip6_plen = htons(24); 
            ip6_hdr.ip6_nxt = IPPROTO_ICMPV6; 
            ip6_hdr.ip6_hlim = 255; 

            memcpy(&ip6_hdr.ip6_src, NetworkUtils::getIP(ifr.ifr_name, AF_INET6), 16);
            // inet_pton(AF_INET6, NetworkUtils::getIP(this->ifr.ifr_name, AF_INET6), &ip6_hdr.ip6_src); 
            memcpy(&ip6_hdr.ip6_dst, dst_ip, 16);

        }

        const struct ip6_hdr* getIP6Header() {
            return &this->ip6_hdr;
        }

  
      
        void buildICMP6(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr) {

            

            struct {
                struct ip6_hdr ip6;
                struct icmp6_hdr icmp6;
                struct nd_neighbor_solicit icmp6_ns;
            } packet;

            memset(&icmp6_hdr, 0, sizeof(icmp6_hdr));
            memset(&packet, 0, sizeof(packet)); 

            packet.ip6 = ip6_hdr;

            icmp6_hdr.icmp6_type = 135; // Тип запроса
            icmp6_hdr.icmp6_code = 0;
            icmp6_hdr.icmp6_cksum = 0; // Проверка контрольной суммы

            memcpy(&packet.icmp6_ns.nd_ns_target, dst_ip, 16);
            packet.icmp6 = icmp6_hdr;

            uint16_t pseudo_header[4 * 4];
            memcpy(pseudo_header, &packet.ip6.ip6_src, 16);
            memcpy(pseudo_header + 8, &packet.ip6.ip6_dst, 16);
            pseudo_header[16] = htons(sizeof(packet) - sizeof(packet.ip6));
            pseudo_header[17] = htons(IPPROTO_ICMPV6);

            // Calculate checksum
            uint16_t checksum = NetworkUtils::checksum((uint16_t *) &pseudo_header, 40);
            checksum += NetworkUtils::checksum((uint16_t *) &packet.icmp6, sizeof(packet) - sizeof(packet.ip6));
            icmp6_hdr.icmp6_cksum  = checksum;

        }

        const struct icmp6_hdr* getICMP6Header() {
            return &this->icmp6_hdr;
        }




        void createNDPPacket(unsigned char* buffer, int *buffer_size, const unsigned char* ipaddr, struct ifreq ifr) {
            struct ethhdr eth;
            struct ip6_hdr ip6;
            struct nd_neighbor_solicit ns;
        
            // ---- 1. Ethernet заголовок ----
            memset(&eth, 0, sizeof(eth));
            memcpy(eth.h_dest, "\x33\x33\xff\x00\x00\x01", 6); // IPv6 multicast для NS
            memcpy(eth.h_source, NetworkUtils::getMAC(&ifr), 6);
            eth.h_proto = htons(ETH_P_IPV6);
        
            // ---- 2. IPv6 заголовок ----
            memset(&ip6, 0, sizeof(ip6));
            ip6.ip6_flow = htonl((6 << 28) | (0 << 20) | 0);
            ip6.ip6_plen = htons(sizeof(ns));
            ip6.ip6_nxt = IPPROTO_ICMPV6;
            ip6.ip6_hlim = 255;
            memcpy(&ip6.ip6_src, NetworkUtils::getIP(ifr.ifr_name, AF_INET6), 16);
            memcpy(&ip6.ip6_dst, ipaddr, 16); // Целевой IPv6 (Multicast)
        
            // ---- 3. ICMPv6 Neighbor Solicitation ----
            memset(&ns, 0, sizeof(ns));
            ns.nd_ns_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;
            ns.nd_ns_hdr.icmp6_code = 0;
            ns.nd_ns_hdr.icmp6_cksum = 0; // Перед расчетом = 0
            memcpy(&ns.nd_ns_target, ipaddr, 16); // Целевой IPv6
        
            // ---- 4. Псевдо-заголовок для контрольной суммы ----
            struct {
                struct in6_addr src;
                struct in6_addr dst;
                uint32_t length;
                uint8_t zero[3];
                uint8_t next_header;
            } pseudo_header;
        
            memcpy(&pseudo_header.src, &ip6.ip6_src, sizeof(struct in6_addr));
            memcpy(&pseudo_header.dst, &ip6.ip6_dst, sizeof(struct in6_addr));
            pseudo_header.length = htonl(sizeof(ns));
            memset(pseudo_header.zero, 0, sizeof(pseudo_header.zero));
            pseudo_header.next_header = IPPROTO_ICMPV6;
        
            // ---- 5. Объединение данных в один буфер ----
            uint8_t temp_buffer[sizeof(pseudo_header) + sizeof(ns)];
            memcpy(temp_buffer, &pseudo_header, sizeof(pseudo_header));
            memcpy(temp_buffer + sizeof(pseudo_header), &ns, sizeof(ns));
        
            // ---- 6. Подсчет контрольной суммы ----
            ns.nd_ns_hdr.icmp6_cksum = NetworkUtils::checksum(temp_buffer, sizeof(temp_buffer));
        
            // ---- 7. Запись данных в выходной буфер ----
            memcpy(buffer, &eth, sizeof(eth));
            memcpy(buffer + sizeof(eth), &ip6, sizeof(ip6));
            memcpy(buffer + sizeof(eth) + sizeof(ip6), &ns, sizeof(ns));
        
            *buffer_size = sizeof(eth) + sizeof(ip6) + sizeof(ns);
        
            std::cout << "NDP Packet Size: " << *buffer_size << " bytes" << std::endl;
            std::cout << "Checksum: " << std::hex << ns.nd_ns_hdr.icmp6_cksum << std::endl;
        }
    
    };


