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
#include <thread>

#include "main.h"


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


void parse_arguments(Options* opts, int argc, char *argv[]){

    int opt;

    while((opt = getopt_long(argc, argv, ":iws", long_options, NULL)) != -1) {
        switch(opt) {
            case 'i':
                if (argv[optind] != NULL && argv[optind][0] != '-') {
                    printf("Interface: %s\n", argv[optind]);
                    opts->interface = argv[optind];
                    printf("Interface: %s\n", opts->interface.c_str());
                } else{
                    printf("No interface specified\n");
                    print_active_interfaces();
                }
                break;
            case 'w':
                if (argv[optind] != NULL && argv[optind][0] != '-') {
                    opts->timeout = atoi(argv[optind]);
                } else {
                    opts->timeout = 5000;
                }
                break;
            case 's':
                if(argv[optind] != NULL && argv[optind][0] != '-') {
                    opts->subnet.push_back(argv[optind]);
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

#define SUCCESS_SENDED 0

std::map<std::string, std::string> ip_mac_map;


void timer(int miliseconds){
    std::this_thread::sleep_for(std::chrono::milliseconds(miliseconds));

}

#include <future>
#include <chrono>
#include <atomic>


std::string process_ip(const unsigned char* ipaddr, ARPHandler& arpHandler, long timeout_ms) {
    if (arpHandler.SendARP(ipaddr) == SUCCESS_SENDED) {
        std::string result_mac = arpHandler.ListenToResponce(ipaddr);
        if (!result_mac.empty()) {
            return result_mac;
        }
    }
    return "not found";
}


int main(int argc, char *argv[]) {

    char errbuf[LIBNET_ERRBUF_SIZE];

    Options opts;
    int opt;

    parse_arguments(&opts, argc, argv);

    signal(SIGINT, interrupt_sniffer);
    signal(SIGQUIT, interrupt_sniffer);
    signal(SIGTERM, interrupt_sniffer);

    if(opts.interface.empty()) {
        print_active_interfaces();
    }

    u_int16_t src_port, dst_port;
    u_int32_t src_addr, dst_addr;
    printf("Interface: %s\n", opts.interface.c_str());  


	int raw_sc = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (raw_sc < 0)
	{
        perror("socket() failed");
		exit(EXIT_FAILURE);
	}
    printf("Interface1:21 %s\n", opts.interface.c_str());  

    int subnet_num = 0;
    
    while(subnet_num < opts.subnet.size()) {
        IpManager ipManager(opts.subnet[subnet_num]);

        std::vector<std::thread> threads;

        while (ipManager.getNextIp()) {
            std::vector<unsigned char> current_ip(ipManager.getCurrentIp(), ipManager.getCurrentIp() + 4);

            threads.emplace_back([&, ip_copy = std::move(current_ip)]() {
                ARPHandler arpHandler(opts.interface);
                ip_mac_map[NetworkUtils::ipToString(ip_copy.data())] = process_ip(ip_copy.data(), arpHandler, opts.timeout);
            });
        }
       

        for (auto& thread : threads) {
            thread.join();
        }


        for (auto& [ip, mac] : ip_mac_map) {
            std::cout << ip << " -> " << mac << std::endl;
        }
        

        subnet_num++;

    }



    return 0;
}
