/*
 * File: transportHandler.cpp
 * Author: Kirill Kurakov <xkurak03>
 * Date Created: 
 * Note:
 */
#include "transportHandler.h"

/**
 * @brief Send request to the network with the specific protocol
 * 
 * @param ipaddr Destination IP address
 * @param dst_mac Destination MAC address
 * 
 * @return int
 */
int TransportHandler::SendRequest(const unsigned char* ipaddr, const unsigned char* dst_mac) {

    struct sockaddr_ll sa;
    int buffer_size = 0;

    // Get the index of the network device 
    memset(&sa, 0, sizeof(struct sockaddr_ll));
    sa.sll_protocol = htons(ETH_P_ALL);

    if ((sa.sll_ifindex = if_nametoindex(this->ifr.ifr_name)) == 0) {
        perror ("if_nametoindex() failed to obtain interface index"); 
        exit(EXIT_FAILURE);
    }

    sa.sll_halen = ETH_ALEN;

    memset(buffer, 0, ETH_FRAME_LEN);
    HeaderBuilder headerBuilder;

    // Build the header based on the protocol. Use headerBuilder to build the different protocol headers.
    switch(this->protocol) {
        case ARP: {

            headerBuilder.buildETH(ARP, ipaddr, NULL, this->ifr);
            headerBuilder.buildARP(ARP, ipaddr, NULL, this->ifr);

            memcpy(buffer, headerBuilder.getETHHeader(), ETHER_HDR_LEN);
            memcpy(buffer + ETHER_HDR_LEN, headerBuilder.getARPHeader(), ARP_HDR_LEN);

            buffer_size = ETHER_HDR_LEN + ARP_HDR_LEN;
            break;
            
        }
        case ICMP: {

            headerBuilder.buildETH(ICMP, ipaddr, dst_mac, this->ifr);
            headerBuilder.buildIP(ICMP, ipaddr, dst_mac, this->ifr);
            headerBuilder.buildICMP(ICMP, ipaddr, dst_mac, this->ifr);

            memcpy(buffer + ETHER_HDR_LEN, headerBuilder.getIPHeader(), IP4_HDR_LEN);
            memcpy(buffer, headerBuilder.getETHHeader(), ETHER_HDR_LEN);
            memcpy(buffer + ETHER_HDR_LEN + IP4_HDR_LEN, headerBuilder.getICMPHeader(), ICMP_HDR_LEN);

            buffer_size = ETHER_HDR_LEN + IP4_HDR_LEN + ICMP_HDR_LEN;
            break;

        }
        case ICMPv6: {
         
            headerBuilder.buildETH(ICMPv6, ipaddr, dst_mac, this->ifr);
            headerBuilder.buildIP6(ICMPv6, ipaddr, dst_mac, this->ifr);
            headerBuilder.buildICMP6(ICMPv6, ipaddr, dst_mac, this->ifr);

            memcpy(buffer, headerBuilder.getETHHeader(), ETHER_HDR_LEN);
            memcpy(buffer + ETHER_HDR_LEN, headerBuilder.getIP6Header(), IP6_HDR_LEN);
            memcpy(buffer + ETHER_HDR_LEN + IP6_HDR_LEN, headerBuilder.getICMP6Header(), ICMP6_HDR_LEN);

            buffer_size = ETHER_HDR_LEN + IP6_HDR_LEN + ICMP6_HDR_LEN;
            break;

        }
        case NDP: {
          
            headerBuilder.buildETH(NDP, ipaddr, NULL, this->ifr);
            headerBuilder.buildIP6(NDP, ipaddr, NULL, this->ifr);
            headerBuilder.buildNS(NDP, ipaddr, NULL, this->ifr);
          
            memcpy(buffer, headerBuilder.getETHHeader(), ETHER_HDR_LEN);
            memcpy(buffer + ETHER_HDR_LEN, headerBuilder.getIP6Header(), IP6_HDR_LEN);
            memcpy(buffer + ETHER_HDR_LEN + IP6_HDR_LEN, headerBuilder.getNSHeader(), 24);

            buffer_size = ETHER_HDR_LEN + IP6_HDR_LEN + NS_HEADER_LEN;
            break;
        }

    }
    
 
    int sock_type = 0;
    // Set the socket type based on the protocol
    switch(this->protocol) {
        case ARP:
            sock_type = ETH_P_ARP;
            break;
        case ICMP:
            sock_type = ETH_P_IP;
            break;
        case ICMPv6:
            sock_type = ETH_P_IPV6;
            break;
        case NDP:
            sock_type = ETH_P_IPV6;
            break;
    }

    // Open socket
    this->sock = socket(AF_PACKET, SOCK_RAW, htons(sock_type));

    if(this->sock < 0){
        perror("Socket error");
        exit(1);
    }
    
    if (sendto(this->sock, buffer, buffer_size, 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll)) < 0) {
        perror("sendto() failed");
        exit(EXIT_FAILURE);
    }

    return SUCCESS_SENDED; 
    
}

/**
 * @brief Test if the ARP response is valid
 * 
 * @param buffer Buffer with the response
 * 
 * @return bool True if the response is valid, false otherwise
 */
bool TransportHandler::testArpResponse(const unsigned char* buffer) {

    struct ethhdr* eth_hdr = (struct ethhdr*)buffer;
    ARP_HDR* arp_hdr = (ARP_HDR*)(buffer + ETHER_HDR_LEN);

    if(ntohs(eth_hdr->h_proto) != ETH_P_ARP) {
        return false;
    }

    // Check that there is a reply for our request
    if(ntohs(arp_hdr->ar_op) != 2){
        return false;
    }

    // Check that the reply sent to our IP and MAC address
    if(memcmp(arp_hdr->ar_tip, NetworkUtils::getIP(this->ifr.ifr_name, AF_INET), 4) != 0 || memcmp(arp_hdr->ar_tha, NetworkUtils::getMAC(&this->ifr), 6) != 0){
        return false;
    }

    // Check that the reply is from the IP address we requested
    if (memcmp(arp_hdr->ar_sip, this->dst_ip, 4) != 0) {
        return false;
    }
    // Save the MAC address
    memcpy(this->dst_mac, eth_hdr->h_source, 6);

    return true; 
}

/**
 * @brief Test if the ICMPv6 response is valid
 * 
 * @param buffer Buffer with the response
 * 
 * @return bool True if the response is valid, false otherwise
 */
bool TransportHandler::testICMPv6Response(const unsigned char* buffer){

    struct ethhdr* eth_hdr = (struct ethhdr *)buffer;
    struct ip6_hdr* ip6_hdr = (struct ip6_hdr*)(buffer + ETHER_HDR_LEN);
    struct icmp6_hdr* icmpv6_hdr = (struct icmp6_hdr*)(buffer + ETHER_HDR_LEN + sizeof(struct ip6_hdr));

    if (ntohs(eth_hdr->h_proto) != ETH_P_IPV6) {
        return false;
    }

    if (ip6_hdr->ip6_nxt != IPPROTO_ICMPV6) {
        return false;
    }

    // Check that the reply is from the IP address we requested
    if (memcmp(&ip6_hdr->ip6_dst, NetworkUtils::getIP(this->ifr.ifr_name, AF_INET6), 16) != 0 || 
        memcmp(&ip6_hdr->ip6_src, this->dst_ip6, 16) != 0) {
        return false;
    }

    if (memcmp(eth_hdr->h_dest, NetworkUtils::getMAC(&this->ifr), 6) != 0) {
        return false;
    }

    // Check that the reply is an Echo Reply
    if (icmpv6_hdr->icmp6_type != 129) { // Echo Reply
        return false;
    }

    return true;

}

/**
 * @brief Test if the ICMP response is valid
 * 
 * @param buffer Buffer with the response
 * 
 * @return bool True if the response is valid, false otherwise
 */
bool TransportHandler::testICMPResponse(const unsigned char* buffer){

    struct ethhdr* eth_hdr = (struct ethhdr*)buffer;
    struct iphdr* ip_hdr = (struct iphdr*)(buffer + ETHER_HDR_LEN);
    ICMP_HDR* icmp_hdr = (ICMP_HDR*)(buffer + ETHER_HDR_LEN + IP4_HDR_LEN);

    if(ntohs(eth_hdr->h_proto) != ETH_P_IP) {
        return false;
    }

    if(ip_hdr->protocol != IPPROTO_ICMP) {
        return false;
    }

    // Check that the reply is from the IP address we requested 
    if(ip_hdr->daddr != *(uint32_t*)NetworkUtils::getIP(this->ifr.ifr_name, AF_INET) || ip_hdr->saddr != *(uint32_t*)this->dst_ip){
        return false;
    }

    if(memcmp(eth_hdr->h_dest, NetworkUtils::getMAC(&this->ifr), 6) != 0) {
        return false;

    }
    // Check that the reply is an Echo Reply
    if(icmp_hdr->type != 0){
        return false;
    }


    return true;
}

/**
 * @brief Test if the NDP response is valid
 * 
 * @param buffer Buffer with the response
 * 
 * @return bool True if the response is valid, false otherwise
 */
bool TransportHandler::testNDPResponse(const unsigned char* buffer) {

    struct ethhdr *eth_hdr = (struct ethhdr*)buffer;
    struct ip6_hdr *ip6_hdr = (struct ip6_hdr*)(buffer + sizeof(struct ethhdr));
    struct nd_neighbor_advert *na_hdr = (struct nd_neighbor_advert*)(buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
    
    if (ntohs(eth_hdr->h_proto) != ETH_P_IPV6) {
        return false;
    }

    if (ip6_hdr->ip6_nxt != IPPROTO_ICMPV6) {
        return false;
    }
    // Check that the reply is from the IP address we requested
    if (memcmp(&ip6_hdr->ip6_dst, NetworkUtils::getIP(this->ifr.ifr_name, AF_INET6), 16) != 0) {
        return false;
    }

    if (memcmp(&ip6_hdr->ip6_src, this->dst_ip6, 16) != 0) {
        return false;
    }
    // Check that the reply is an Echo Reply
    if (na_hdr->nd_na_hdr.icmp6_type != ND_NEIGHBOR_ADVERT) {
        return false;
    }

    // Find the requested Mac adress in the response in the opt header what is in the na_hdr
    struct nd_opt_hdr *opt_hdr = (struct nd_opt_hdr*)((unsigned char*)na_hdr + sizeof(struct nd_neighbor_advert));
    if (opt_hdr->nd_opt_type == ND_OPT_TARGET_LINKADDR) {
        unsigned char *received_mac = (unsigned char *)(opt_hdr + 1);
        memcpy(this->dst_mac, received_mac, 6);
    }

    return true;
}

/**
 * @brief Listen to the response from the network
 * 
 * @param timeout_ms Timeout in milliseconds
 * 
 * @return int
 */
int TransportHandler::ListenToResponce(long int timeout_ms) {

    while(1){
        memset(buffer, 0, BUFSIZE);
        // set socket option for timeout 
        struct timeval timeout;
        timeout.tv_sec = timeout_ms / 1000; 
        timeout.tv_usec = (timeout_ms % 1000) * 1000;

        setsockopt(this->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        
        int length = recvfrom(this->sock, this->buffer, BUFSIZE, 0, NULL, NULL);

        // Check if the response was received, or if the response was not received because of timeout
        if (length < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                return false;
            } else {
                perror("recvfrom() failed");
                break;
            }
        }

        // Test that this is response for our request based on the protocol
        switch(this->protocol) {
            case ARP:
                if (!this->testArpResponse(buffer)){
                    continue;
                }
                break;
            case ICMP:
                if (!this->testICMPResponse(buffer)){
                    continue;
                }
                break;
            case ICMPv6:
                if(!this->testICMPv6Response(buffer)){
                    continue;
                }
                break;
            case NDP:
                if(!this->testNDPResponse(buffer)){
                    continue;
                }
                break;
        }

        return SUCCESS_RECEIVED;
    }

    return false;
}

/**
 * @brief Get the destination MAC address
 * 
 * @return std::string
 */
std::string TransportHandler::GetDestMAC() {

    return NetworkUtils::macToString(this->dst_mac);
}
