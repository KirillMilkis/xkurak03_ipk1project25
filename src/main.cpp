
#include "main.h"

/**
 * @brief Function that handle different interrupt signals like Ctrl + C
 * 
 * @param signum 
 * 
 * @return void
 */
void interrupt_sniffer(int signum){
    (void)signum;
    printf("Interrupt signal received. Exiting...\n");
    exit(EXIT_SUCCESS);
}

/**
 * @brief Function that parse arguments from command line
 * 
 * @param opts
 * @param argc
 * @param argv
 * 
 * @return void
 */
void parse_arguments(Options* opts, int argc, char *argv[]){

    int opt;

    opts->timeout = 5000;

    while((opt = getopt_long(argc, argv, "i::w::s::h", long_options, NULL)) != -1) {
        switch(opt) {
            case 'i':
                if (optarg == NULL && optind < argc
                    && argv[optind][0] != '-'){
                    opts->interface = argv[optind++];
                } else if(optarg != NULL){
                    printf("Interface: %s\n", optarg);
                    opts->interface = optarg;
                }
                break;
            case 'w':
                if (optarg == NULL && optind < argc
                    && argv[optind][0] != '-'){
                    opts->timeout = atoi(argv[optind++]);
                } else if(optarg != NULL){
                    opts->timeout = atoi(optarg);
                } 
                break;
            case 's':
                if (optarg == NULL && optind < argc
                    && argv[optind][0] != '-'){
                    opts->subnet.push_back(argv[optind++]);
                } else if(optarg != NULL){
                    opts->subnet.push_back(optarg);
                }
                break;
            case 'h':
                fprintf(stderr, "Usage: %s [-i interface | --interface interface] {-w timeout} [-s ipv4-subnet | -s ipv6-subnet | --subnet ipv4-subnet | --subnet ipv6-subnet]\n", argv[0]);
                exit(EXIT_SUCCESS);
                case '?':
                fprintf(stderr, "Unknown option: %s\n", argv[optind - 1]);
                break;
            case ':':
                fprintf(stderr, "Missing argument for %s\n", argv[optind - 1]);
                break;
        }
    }

    if(opts->subnet.empty()) {
        fprintf(stderr, "No subnet specified\n");
        exit(EXIT_FAILURE);
    }

    if(opts->interface.empty()) {
        NetworkUtils::print_active_interfaces();
        fprintf(stderr, "No interface specified\n");
        exit(EXIT_FAILURE);
    }

    if(opts->timeout < 0) {
        fprintf(stderr, "Invalid timeout value\n");
        exit(EXIT_FAILURE);
    }

}

/**
 * @brief Function that process ARP and NDP request
 * 
 * @param target_ip_char
 * @param arpHandler
 * @param timeout_ms
 * 
 * @return bool
 */
bool process_ar(const unsigned char* target_ip_char, TransportHandler* arpHandler, long timeout_ms) {

    if (arpHandler->SendRequest(target_ip_char, nullptr) == SUCCESS_SENDED) {
        if(arpHandler->ListenToResponce(timeout_ms) == SUCCESS_RECEIVED) {

           return true;
        }
    }
    
    return false;
}

bool process_icmp(const unsigned char* target_ip_char, std::string target_mac_string, TransportHandler& icmpHandler, long timeout_ms) {

    unsigned char target_mac_char[6];
    if(!NetworkUtils::macStringToBytes(target_mac_string, target_mac_char)){
        return false;
    }

    if (icmpHandler.SendRequest(target_ip_char, target_mac_char) == SUCCESS_SENDED){
        if (icmpHandler.ListenToResponce(timeout_ms) == SUCCESS_RECEIVED) {
           return true;
        } 
    }   

    return false;

}


int scan_adresses(int ip_type, std::map<std::string, std::string>& ip_mac_map, std::map<std::string, bool>& ip_icmp_reply_map, std::vector<unsigned char> current_ip, Options opts) {

        TransportHandler transportHandlerAdrrRes(opts.interface, protocol_rules[ip_type].first);

        const unsigned char* target_ip_char = current_ip.data();
        
        std::string target_ip_string = NetworkUtils::ipToString(target_ip_char, ip_type);

        if (process_ar(target_ip_char, &transportHandlerAdrrRes, opts.timeout)){
            ip_mac_map[target_ip_string] =  transportHandlerAdrrRes.GetDestMAC();   

        } else {
            ip_mac_map[target_ip_string] = "not found"; 
        }

        TransportHandler transportHandlerIcmp(opts.interface, protocol_rules[ip_type].second);

        std::string target_mac_string = ip_mac_map[target_ip_string];
        
        if (target_mac_string != "not found"){
            ip_icmp_reply_map[target_ip_string] = process_icmp(target_ip_char, target_mac_string, transportHandlerIcmp, opts.timeout);
        
        } else {
            ip_icmp_reply_map[target_ip_string] = false;
        }

        return 0;

}

#include <queue>
#include <functional>

std::mutex mtx;
std::condition_variable cv;
std::queue<std::function<void()>> tasks;
size_t max_threads = 50;
size_t active_threads = 0;
std::atomic<bool> stop_threads(false);

void thread_worker() {
    while (true) {
        std::function<void()> task;

        {
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait(lock, [] { return !tasks.empty() || stop_threads.load(); });

            if (stop_threads.load() && tasks.empty()) {
                break; 
            }

            task = tasks.front();
            tasks.pop();
            ++active_threads;
        }

        if (task) {
            task(); 
        }

        {
            std::lock_guard<std::mutex> lock(mtx);
            --active_threads;
        }
    }
}

int print_results(std::map<std::string, std::string>& ip_mac_map, std::map<std::string, bool>& ip_icmp_reply_map) {

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

    return 1;
}


int main(int argc, char *argv[]) {

    Options opts;

    parse_arguments(&opts, argc, argv);

    signal(SIGINT, interrupt_sniffer);
    signal(SIGQUIT, interrupt_sniffer);
    signal(SIGTERM, interrupt_sniffer);

    std::map<std::string, std::string> ip_mac_map;
    std::map<std::string, std::string> ip_mac_map_v6;
    std::map<std::string, bool> ip_icmp_reply_map;
    std::map<std::string, bool> ip_icmp_reply_map_v6;

    printf("Interface: %s\n", opts.interface.c_str());  

    IpManager ipManager(opts.subnet);

    ipManager.printAllSubnets();


    do {

        while (!tasks.empty()) {
            tasks.pop();
        }
       

        while (ipManager.getNextIp() !=  nullptr) {
            
            std::lock_guard<std::mutex> lock(mtx);

            std::vector<unsigned char> current_ip(ipManager.getCurrentIp(), ipManager.getCurrentIp() + (IpManager::isIPv6(ipManager.getCurrentIpString()) ? 16 : 4));
           
            tasks.push([&, current_ip_copy = std::move(current_ip)]() {
                if(IpManager::isIPv6(ipManager.getCurrentIpString())) {
                    scan_adresses(AF_INET6, ip_mac_map_v6, ip_icmp_reply_map_v6, current_ip_copy, opts);
                } else {
                    scan_adresses(AF_INET, ip_mac_map, ip_icmp_reply_map, current_ip_copy, opts);
                }

            });

            cv.notify_one();

        }      

        std::vector<std::thread> threads;
        for (size_t i = 0; i < max_threads; ++i) {
            threads.emplace_back(thread_worker);
        }

        {
            std::lock_guard<std::mutex> lock(mtx);
            stop_threads.store(true); 
        }
        cv.notify_all(); 
       
        for (auto& thread : threads) {
            thread.join();
        }

        stop_threads.store(false);
        

    } while(ipManager.useNextSubnet());

    
    print_results(ip_mac_map, ip_icmp_reply_map);
    print_results(ip_mac_map_v6, ip_icmp_reply_map_v6);

    return 0;
}
