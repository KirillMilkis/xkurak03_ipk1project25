#define no_argument 0
#define required_argument 1
#define optional_argument 2

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <iostream>
#include <libnet.h>
#include <pcap.h>


void interrupt_sniffer(int signum){
    // Function that handle different interrupt signals like Ctrl + C
    printf("Interrupt signal received. Exiting...\n");
    // pcap_breakloop(pcap_descriptor);
    // pcap_close(pcap_descriptor);
    exit(EXIT_SUCCESS);
}


static struct option long_options[] = {
    {"interface", required_argument, NULL, 'i'},
    {"port", optional_argument, NULL, 'p'},
    {"port-source", optional_argument, NULL, 1},
    {"port-destination", optional_argument, NULL, 2},
    {"arp", no_argument, NULL, 3},
    {"ndp", no_argument, NULL, 4},
    {"icmp4", no_argument, NULL, 5},
    {"icmp6", no_argument, NULL, 6},
    {"igmp", no_argument, NULL, 7},
    {"mld", no_argument, NULL, 8},
    {"number", optional_argument, NULL, 'n'},
    {0, 0, 0, 0}
};

// using namespace std;

typedef struct options{
    std::string interface;
    long int timeout;
    std::vector<std::string> subnet;

} Options;


pcap_if_t* get_interrfaces() {
    pcap_if_t *allinfs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if(pcap_findalldevs(&allinfs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(EXIT_FAILURE);

    }
    return allinfs;
}

int print_active_interfaces() {
    pcap_if_t *alldevsp;

    alldevsp = get_interrfaces();

     while(alldevsp != NULL) {
        std::cout << alldevsp->name << std::endl;

        if(alldevsp->description != NULL) {
            std::cout << alldevsp->description << std::endl;
        } else{
            std::cout << "No description available" << std::endl;
        }

        alldevsp = alldevsp->next;

    }
    
    pcap_freealldevs(alldevsp);

    return 0;
}


void parse_arguments(Options opts, int argc, char *argv[]){

    while((opt = getopt_long(argc, argv, ":iws", long_options, NULL)) != -1) {
        switch(opt) {
            case 'i':
                if (argv[optind] != NULL && argv[optind][0] != '-') {
                    opts.interface = argv[optind];
                } else{
                    print_active_interfaces();
                }
                break;
            case 'w':
                if (argv[optind] != NULL && argv[optind][0] != '-') {
                    opts.timeout = atoi(argv[optind]);
                } else {
                    opts.timeout = 5000;
                }
                break;
            case 's':
                if(argv[optind] != NULL && argv[optind][0] != '-') {
                    opts.subnet.push_back(argv[optind]);
                }
                break;
            case '?':
                fprintf(stderr, "Unknown option: %s\n", argv[optind - 1]);
                break;
            case ':':
                fprintf(stderr, "Missing argument for %s\n", argv[optind - 1]);
                break;
        }
    }


}


int main(int argc, char *argv[]) {

    char errbuf[LIBNET_ERRBUF_SIZE];

    Options opts;
    int opt;

    parse_arguments(opts, argc, argv);


    if(opts.interface.empty()) {
        print_active_interfaces();
    }

    u_int16_t src_port, dst_port;
    u_int32_t src_addr, dst_addr;


	int raw_sc = socket(AF_INET, SOCK_RAW, 0);
	if (raw_sc < 0)
	{
		exit(EXIT_FAILURE);
	}else{
		return raw_sc;
	}

    struct sockaddr_in sin;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr("27.0.0.1");

    // std::cout << "Interface: " << opts.interface << std::endl;
    // std::cout << "Timeout: " << opts.timeout << std::endl;

    // libnet_t *l;

    // l = libnet_init(LIBNET_RAW4, NULL, errbuf);

    // if ( l == NULL ) {
    //     fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
    //     exit(EXIT_FAILURE);
    // }
    

    signal(SIGINT, interrupt_sniffer);
    signal(SIGQUIT, interrupt_sniffer);
    signal(SIGTERM, interrupt_sniffer);




    for(auto &s : opts.subnet) {
        std::cout << "Subnet: " << s << std::endl;
    }

    return 0;
}
