
#include "TransportHandler.h"


int TransportHandler::SendRequest(const unsigned char* ipaddr) {
    // Function to send ARP packets

    ETH_HDR eth_hdr;
    ARP_HDR arp_hdr;
    const unsigned char broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // Broadcast MAC
    struct sockaddr_ll sa;

    int buffer_size;

    // Get the index of the network device

    memset(&sa, 0, sizeof(struct sockaddr_ll));
    sa.sll_protocol = htons(ETH_P_ALL);  
    if ((sa.sll_ifindex = if_nametoindex (this->ifr.ifr_name)) == 0) {
        perror ("if_nametoindex() failed to obtain interface index");
        exit(EXIT_FAILURE);
      }
    sa.sll_halen = ETH_ALEN;

    memset(buffer, 0, ETH_FRAME_LEN);

    switch(this->protocol) {
        case ARP:
            eth_hdr = new ETHHeader(this->iface);
            eth_hdr->build();
            memset(buffer, eth_hdr->getHeader(), ETHER_HDR_LEN);

            arp_hdr = new ARPHeader(this->iface);
            arp_hdr->build();
            memet(buffer + ETHER_HDR_LEN, arp_hdr->getHeader(), ARP_HDR_LEN);

            buffer_size  = ETHER_HDR_LEN + ARP_HDR_LEN;
            break;
            
        
        case ICMP:
            eth_hdr = new ETHHeader(this->iface);
            eth_hdr->build();
            memset(buffer, eth_hdr->getHeader(), ETHER_HDR_LEN);

            ip_hdr = new IPHeader(this->iface);
            ip_hdr->build(ipaddr, this->ifr);
            memet(buffer + ETHER_HDR_LEN, ip_hdr->getHeader(), IP4_HDR_LEN);
            
            icmp_hdr = new ICMPHeader(this->iface);
            icmp_hdr->build();
            memet(buffer + ETHER_HDR_LEN + IP4_HDR_LEN, icmp_hdr->getHeader(), ICMP_HDR_LEN);

            buffer_size = ETHER_HDR_LEN + IP4_HDR_LEN + ICMP_HDR_LEN;
            break;


        case ICMPv6:
            eth_hdr = new ETHHeader(this->iface);
            eth_hdr->build();
            memset(buffer, eth_hdr->getHeader(), ETHER_HDR_LEN);

            ip6_hdr = new IP6Header(this->iface);
            ip6_hdr->build(ipaddr, this->ifr);
            memet(buffer + ETHER_HDR_LEN, ip6_hdr->getHeader(), IP6_HDR_LEN);
            
            icmp6_hdr = new ICMP6Header(this->iface);
            icmp6_hdr->build();
            memet(buffer + ETHER_HDR_LEN + IP6_HDR_LEN, icmp6_hdr->getHeader(), ICMP6_HDR_LEN);

            buffer_size = ETHER_HDR_LEN + IP6_HDR_LEN + ICMP6_HDR_LEN;
            break;

        case NDP:

            eth_hdr = new ETHHeader(this->iface);
            eth_hdr->build();
            memset(buffer, eth_hdr->getHeader(), ETHER_HDR_LEN);

            ip6_hdr = new IP6Header(this->iface);
            ip6_hdr->build(ipaddr, this->ifr);
            memet(buffer + ETHER_HDR_LEN, ip6_hdr->getHeader(), IP6_HDR_LEN);
            
            icmp6_hdr = new ICMP6Header(this->iface);
            icmp6_hdr->build();
            memet(buffer + ETHER_HDR_LEN + IP6_HDR_LEN, icmp6_hdr->getHeader(), ICMP6_HDR_LEN);

            buffer_size = ETHER_HDR_LEN + IP6_HDR_LEN + ICMP6_HDR_LEN;
            break;


    }
    
    memset(buffer, 0, ETH_FRAME_LEN);  // Заполняем буфер кадра
    memcpy(buffer, &eth_hdr, ETHER_HDR_LEN);
    memcpy(buffer + ETHER_HDR_LEN, &arp_hdr, ARP_HDR_LEN);


    if (sendto(this->socket, buffer, buffer_size, 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll)) < 0) {
        perror("sendto() failed");
        exit(EXIT_FAILURE);
    }

    return SUCCESS_SENDED; //
    
}