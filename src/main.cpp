#define no_argument 0
#define required_argument 1
#define optional_argument 2

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>

#include <iostream>
#include <libnet.h>
#include <pcap.h>
#include <thread>
#include <future>
#include <chrono>
#include <atomic>

#include "main.h"
#include "transportHandler.h"

#include <vector>


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
    {"wait", optional_argument, NULL, 'w'},
    {"subnet", required_argument, NULL, 's'},
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

#define SUCCESS_SENDED 3

std::map<std::string, std::string> ip_mac_map;
std::map<std::string, std::string> ip_mac_map_v6;
std::map<std::string, bool> ip_icmp_reply_map;
std::map<std::string, bool> ip_icmp_reply_map_v6;

std::map<uint8_t, std::pair<uint8_t, uint8_t>> protocol_rules = {
    {AF_INET, {1, 2}},
    {AF_INET6, {3, 4}},
};

void timer(int miliseconds){
    std::this_thread::sleep_for(std::chrono::milliseconds(miliseconds));

}


bool process_ar(const unsigned char* target_ip_char, TransportHandler* arpHandler, long timeout_ms) {

    if (arpHandler->SendRequest(target_ip_char, nullptr) == SUCCESS_SENDED) {
        if(arpHandler->ListenToResponce(target_ip_char, timeout_ms) == SUCCESS_RECEIVED) {

           return true;
        }
    }
    
    return false;
}

bool process_icmp(const unsigned char* target_ip_char, std::string target_ip_string, TransportHandler& icmpHandler, long timeout_ms) {
    unsigned char target_mac_char[6];
    if(!NetworkUtils::macStringToBytes(ip_mac_map[target_ip_string], target_mac_char)){
        return false;
    }
    // const unsigned char* target_mac_char = (const unsigned char*)ip_mac_map[target_ip_string].c_str();

    if (icmpHandler.SendRequest(target_ip_char, target_mac_char) == SUCCESS_SENDED){
        if (icmpHandler.ListenToResponce(target_ip_char, timeout_ms) == SUCCESS_RECEIVED) {
           return true;
        } 
    }   

    return false;

}

bool process_ndp(const unsigned char* target_ip_char, TransportHandler* ndpHandler, long timeout_ms) {
   
    if (ndpHandler->SendRequest(target_ip_char, nullptr) == SUCCESS_SENDED) {
        if(ndpHandler->ListenToResponce(target_ip_char, timeout_ms) == SUCCESS_RECEIVED) {
           
            return true; //
        }
    }
    
    return false;
}

bool process_icmp6(const unsigned char* target_ip_char, std::string target_ip_string, TransportHandler& icmpHandler, long timeout_ms) {
    unsigned char target_mac_char[6];
    if(!NetworkUtils::macStringToBytes(ip_mac_map_v6[target_ip_string], target_mac_char)){
        return false;
    };

    if (icmpHandler.SendRequest(target_ip_char, target_mac_char) == SUCCESS_SENDED){
        if (icmpHandler.ListenToResponce(target_ip_char, timeout_ms) == SUCCESS_RECEIVED) {
           return true;
        } 
    }   

    return false;

}

Options opts;


int scan_adresses(int ip_type, std::map<std::string, std::string>& ip_mac_map, std::map<std::string, bool>& ip_icmp_reply_map, std::vector<unsigned char> current_ip, Options optsssss) {

        TransportHandler transportHandlerAdrrRes(opts.interface, protocol_rules[ip_type].first);

        const unsigned char* target_ip_char = current_ip.data();
        
        std::string target_ip_string = NetworkUtils::ipToString(target_ip_char, ip_type);

        if (process_ar(target_ip_char, &transportHandlerAdrrRes, opts.timeout)){
            ip_mac_map[target_ip_string] =  transportHandlerAdrrRes.GetDestMAC();   

        } else {
            ip_mac_map[target_ip_string] = "not found"; 
        }

        TransportHandler transportHandlerIcmp(opts.interface, protocol_rules[ip_type].second);
        
        if (ip_mac_map[target_ip_string] != "not found"){
            ip_icmp_reply_map[target_ip_string] = process_icmp(target_ip_char, target_ip_string, transportHandlerIcmp, opts.timeout);
        
        } else {
            ip_icmp_reply_map[target_ip_string] = false;
        }

        return 0;

}


std::mutex mtx;
std::condition_variable cv;
std::queue<std::function<void()>> tasks;
size_t max_threads = 50;


void thread_worker() {
    while (true) {
        std::function<void()> task;

        // Блокировка для доступа к очереди
        {
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait(lock, [] { return !tasks.empty(); });

            task = tasks.front();
            tasks.pop();
        }

        if (task) {
            task(); // Выполняем задачу
        }
    }
}


int main(int argc, char *argv[]) {

    char errbuf[LIBNET_ERRBUF_SIZE];

    // Options opts;
    int opt;

    parse_arguments(&opts, argc, argv);

    signal(SIGINT, interrupt_sniffer);
    signal(SIGQUIT, interrupt_sniffer);
    signal(SIGTERM, interrupt_sniffer);

    if(opts.interface.empty()) {
        print_active_interfaces();
    }

    printf("Interface: %s\n", opts.interface.c_str());  


    IpManager ipManager(opts.subnet);
    ipManager.printAllSubnets();
    
    do {

        std::vector<std::thread> threads;

        while (ipManager.getNextIp() !=  nullptr) {

            if(IpManager::isIPv6(ipManager.getCurrentIpString())) {

                std::vector<unsigned char> current_ip(ipManager.getCurrentIp(), ipManager.getCurrentIp() + 16);

                threads.emplace_back([&, current_ip_copy = std::move(current_ip)]() {

                    scan_adresses(AF_INET6, ip_mac_map_v6, ip_icmp_reply_map_v6, current_ip_copy, opts);

                });

                // threads.emplace_back([&, ip_copy = std::move(current_ip)]() {

                //     TransportHandler transportHandlerNDP(opts.interface, 3);
    
                //     const unsigned char* target_ip_char = ip_copy.data();
                    
                //     std::string target_ip_string = NetworkUtils::ipToString(target_ip_char, AF_INET6);
    
                //      if (process_ndp(target_ip_char, &transportHandlerNDP, opts.timeout)){
                //         ip_mac_map_v6[target_ip_string] =  transportHandlerNDP.GetDestMAC();   

                //      } else {
                //          ip_mac_map_v6[target_ip_string] = "not found";
                //      }
    
                //     TransportHandler transportHandlerIcmpV6(opts.interface, 4);
                    
                //     if (ip_mac_map_v6[target_ip_string] != "not found"){
                //         ip_icmp_reply_map_v6[target_ip_string] = process_icmp6(target_ip_char, target_ip_string, transportHandlerIcmpV6, opts.timeout);
                    
                //     } else {
                //         ip_icmp_reply_map_v6[target_ip_string] = false;
                //     }
    
                // });


            } else {

                std::vector<unsigned char> current_ip(ipManager.getCurrentIp(), ipManager.getCurrentIp() + 4);

                threads.emplace_back([&, current_ip_copy = std::move(current_ip)]() {

                    scan_adresses(AF_INET, ip_mac_map, ip_icmp_reply_map, current_ip_copy, opts);

                });

                // threads.emplace_back([&, ip_copy = std::move(current_ip)]() {

                //     TransportHandler transportHandlerArp(opts.interface, 1);
    
                //     const unsigned char* target_ip_char = ip_copy.data();
                    
                //     std::string target_ip_string = NetworkUtils::ipToString(target_ip_char, AF_INET);
    
                //     if(process_arp(target_ip_char, &transportHandlerArp, opts.timeout)){
                //         ip_mac_map[target_ip_string] = transportHandlerArp.GetDestMAC();
                //     } else {
                //         ip_mac_map[target_ip_string] = "not found";
                //     }

                //     TransportHandler transportHandlerIcmp(opts.interface, 2);
                    
                //     if (ip_mac_map[target_ip_string] != "not found"){
       
                //         ip_icmp_reply_map[target_ip_string] = process_icmp(target_ip_char, target_ip_string, transportHandlerIcmp, opts.timeout);
                    
                //     } else {
    
                //         ip_icmp_reply_map[target_ip_string] = false;
                //     }
    
                // });


            }   

            
        }
       

       
        for (auto& thread : threads) {
            thread.join();
        }

       
        

    } while(ipManager.useNextSubnet());

    


    for (auto& [ip, mac] : ip_mac_map) {
        unsigned char mac_c[6];
        
        printf("%s arp ", ip.c_str());
        
        if(mac != "not found"){
            sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac_c[0], &mac_c[1], &mac_c[2], &mac_c[3], &mac_c[4], &mac_c[5]);
            printf("(%02x-%02x-%02x-%02x-%02x-%02x)", mac_c[0], mac_c[1], mac_c[2], mac_c[3], mac_c[4], mac_c[5]);
        } else {
            printf("FAIL");
        }
        
        printf(", ");

        if(ip_icmp_reply_map[ip]){
            printf("icmp OK\n");
        } else {
            printf("icmp FAIL\n");
        }

    }

    for (auto& [ip, mac] : ip_mac_map_v6) {
        unsigned char mac_c[6];
        
        printf("%s arp ", ip.c_str());
        
        if(mac != "not found"){
            sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac_c[0], &mac_c[1], &mac_c[2], &mac_c[3], &mac_c[4], &mac_c[5]);
            printf("(%02x-%02x-%02x-%02x-%02x-%02x)", mac_c[0], mac_c[1], mac_c[2], mac_c[3], mac_c[4], mac_c[5]);
        } else {
            printf("FAIL");
        }
        
        printf(", ");

        if(ip_icmp_reply_map_v6[ip]){
            printf("icmp OK\n");
        } else {
            printf("icmp FAIL\n");
        }

    }



    return 0;
}
