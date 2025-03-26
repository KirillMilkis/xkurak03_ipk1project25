/*
 * File: headerBuilder.cpp
 * Author: Kirill Kurakov <xkurak03>
 * Date Created: 
 * Note:
 */
#include "headerBuilder.h" 

/**
 * @brief Construct a new Ethernet header
 * 
 * @param protocol Protocol
 * @param dst_ip Destination IP address
 * @param dst_mac Destination MAC address
 * @param ifr Interface request structure
 * 
 * @return void
 */
void HeaderBuilder::buildETH(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr) {

    // Ignore unused parameters
    (void)protocol;
    (void)dst_mac;
    (void)dst_ip;
    (void)ifr;

    memset(&this->eth_hdr, 0, sizeof(this->eth_hdr));

    switch(protocol){
        case ARP:
            this->eth_hdr.h_proto = htons(ETH_P_ARP);
            break;
        case ICMPv6:
        case NDP:
            this->eth_hdr.h_proto = htons(ETH_P_IPV6);
            break;
        case ICMP:
        default:
            this->eth_hdr.h_proto = htons(ETH_P_IP);
            break;
    }


    switch(protocol){
        case ARP:
            memcpy(this->eth_hdr.h_dest, broadcast_mac, 6); 
            break;
        case NDP:
            memcpy(this->eth_hdr.h_dest, "\x33\x33\xff\x00\x00\x01", 6);
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

/**
 * @brief Get Ethernet header
 * 
 * @return const struct ethhdr* 
 */
const struct ethhdr* HeaderBuilder::getETHHeader() {
    return &this->eth_hdr;
}

/**
 * @brief Construct a new ARP header
 * 
 * @param protocol Protocol
 * @param dst_ip Destination IP address
 * @param dst_mac Destination MAC address
 * @param ifr Interface request structure
 * 
 * @return void
 */
void HeaderBuilder::buildARP(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr) {

    (void)protocol;
    (void)dst_mac;
    (void)dst_ip;
    (void)ifr;


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

/**
 * @brief Get ARP header. We have to transform the struct to const struct arphdr* because in arphdr
 * we cannot fill the ar_sha, ar_sip, ar_tha and ar_tip fields, that impotant to send this request.
 * 
 * @return const struct arphdr* 
 */
const struct arphdr* HeaderBuilder::getARPHeader() {
    return reinterpret_cast<const struct arphdr*>(&this->arp_hdr); 
}

/**
 * @brief Construct a new IP header
 * 
 * @param protocol Protocol
 * @param dst_ip Destination IP address
 * @param dst_mac Destination MAC address
 * @param ifr Interface request structure
 * 
 * @return void
 */
void HeaderBuilder::buildIP(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr) {

    (void)protocol;
    (void)dst_mac;
    (void)dst_ip;
    (void)ifr;


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

/**
 * @brief Get IP header
 * 
 * @return const struct iphdr*
 */
const struct iphdr* HeaderBuilder::getIPHeader() {
    return &this->ip_hdr;
}

/**
 * @brief Construct a new ICMP header
 * 
 * @param protocol Protocol
 * @param dst_ip Destination IP address
 * @param dst_mac Destination MAC address
 * @param ifr Interface request structure
 * 
 * @return void
 */
void HeaderBuilder::buildICMP(int protocol, const unsigned char* dst_ip,const  unsigned char* dst_mac, struct ifreq ifr) {

    (void)protocol;
    (void)dst_mac;
    (void)dst_ip;
    (void)ifr;


    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.type = 8;
    icmp_hdr.code = 0;
    this->icmp_hdr_id = getpid();
    icmp_hdr.id = this->icmp_hdr_id;
    icmp_hdr.seq = htons(1);
    icmp_hdr.checksum = NetworkUtils::checksum(&icmp_hdr, sizeof(icmp_hdr));

}

/**
 * @brief Get ICMP header
 * 
 * @return const struct icmp_hdr*
 */
const struct icmp_hdr* HeaderBuilder::getICMPHeader() {
    return &this->icmp_hdr;
}

/**
 * @brief Construct a new IPv6 header
 * 
 * @param protocol Protocol
 * @param dst_ip Destination IP address
 * @param dst_mac Destination MAC address
 * @param ifr Interface request structure
 * 
 * @return void
 */
void HeaderBuilder::buildIP6(int protocol, const unsigned char* dst_ip,const  unsigned char* dst_mac, struct ifreq ifr) {
    // Ignore unused parameters
    (void)protocol;
    (void)dst_mac;
    (void)dst_ip;
    (void)ifr;

    this->ip6_hdr.ip6_flow = htonl((6 << 28) | (0 << 20) | 0);
    this->ip6_hdr.ip6_plen = htons(24); 
    this->ip6_hdr.ip6_nxt = IPPROTO_ICMPV6; 
    this->ip6_hdr.ip6_hlim = 255; 

    memcpy(&this->ip6_hdr.ip6_src, NetworkUtils::getIP(ifr.ifr_name, AF_INET6), 16);
    memcpy(&this->ip6_hdr.ip6_dst, dst_ip, 16);

    
}

/**
 * @brief Get IPv6 header
 * 
 * @return const struct ip6_hdr*
 */
const struct ip6_hdr* HeaderBuilder::getIP6Header() {
    return &this->ip6_hdr;
}

/**
 * @brief Construct a new Neighbor Solicitation header
 * 
 * @param protocol Protocol
 * @param dst_ip Destination IP address
 * @param dst_mac Destination MAC address
 * @param ifr Interface request structure
 * 
 * @return void
 */
void HeaderBuilder::buildNS(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr) {
    // Ignore unused parameters
    (void)protocol;
    (void)dst_mac;
    (void)dst_ip;
    (void)ifr;

    memset(&ns, 0, sizeof(ns));
    this->ns.nd_ns_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;
    this->ns.nd_ns_hdr.icmp6_code = 0;
    this->ns.nd_ns_hdr.icmp6_cksum = 0;
    memcpy(&ns.nd_ns_target, dst_ip, 16); 

    // We have to change ip6 header length to the length of the NS header
    this->ip6_hdr.ip6_plen = htons(sizeof(ns));

    // NS header requeres special type of header to calculate checksum
    struct pseudo_header pseudo_header;

    memset(&pseudo_header, 0, sizeof(pseudo_header));
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

/**
 * @brief Get Neighbor Solicitation header
 * 
 * @return const struct nd_neighbor_solicit*
 */
const struct nd_neighbor_solicit* HeaderBuilder::getNSHeader() {
    return &this->ns;
}


/**
 * @brief Construct a new ICMPv6 header
 * 
 * @param protocol Protocol
 * @param dst_ip Destination IP address
 * @param dst_mac Destination MAC address
 * @param ifr Interface request structure
 * 
 * @return void
 */
void HeaderBuilder::buildICMP6(int protocol, const unsigned char* dst_ip, const unsigned char* dst_mac, struct ifreq ifr) {

    (void)protocol;
    (void)dst_mac;
    (void)dst_ip;
    (void)ifr;

    memset(&this->icmpv6_hdr, 0, sizeof(icmpv6_hdr));

    this->icmpv6_hdr.icmp6_type = 128;
    this->icmpv6_hdr.icmp6_code = 0;
    this->icmpv6_hdr.icmp6_cksum = 0;
    this->icmpv6_hdr.icmp6_dataun.icmp6_un_data16[0] = htons(getpid()); 
    this->icmpv6_hdr.icmp6_dataun.icmp6_un_data16[1] = htons(1);

    // We have to change ip6 header length to the length of the NS header
    this->ip6_hdr.ip6_plen = htons(sizeof(icmpv6_hdr));

    // NS header requeres special type of header to calculate checksum
    struct pseudo_header pseudo_header;
    memset(&pseudo_header, 0, sizeof(pseudo_header));
    memset(&pseudo_header, 0, sizeof(pseudo_header));
    memcpy(&pseudo_header.src, &this->ip6_hdr.ip6_src, sizeof(struct in6_addr));
    memcpy(&pseudo_header.dst, &this->ip6_hdr.ip6_dst, sizeof(struct in6_addr));
    pseudo_header.length = htonl(sizeof(this->icmpv6_hdr));
    pseudo_header.next_header = IPPROTO_ICMPV6;
    
    uint8_t temp_buffer[sizeof(pseudo_header) + sizeof(this->icmpv6_hdr)];
    memcpy(temp_buffer, &pseudo_header, sizeof(pseudo_header));
    memcpy(temp_buffer + sizeof(pseudo_header), &this->icmpv6_hdr, sizeof(this->icmpv6_hdr));

    this->icmpv6_hdr.icmp6_cksum = NetworkUtils::checksum((uint16_t*)temp_buffer, sizeof(temp_buffer));
}

/**
 * @brief Get ICMPv6 header
 * 
 * @return const struct icmp6_hdr*
 */
const struct icmp6_hdr* HeaderBuilder::getICMP6Header() {
    return &this->icmpv6_hdr; 
}






