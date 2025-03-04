

typedef struct options{
    bool udp;
    bool tcp;
    bool arp;
    bool ndp;
    bool icmp4;
    bool icmp6;
    bool igmp;
    bool mld;
    long port_source;
    long port_dest;
    long port;
    int packet_num;
    char interface[256];
} Options;