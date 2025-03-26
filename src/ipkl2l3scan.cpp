/*
 * File: ipkl2l3scan.cpp
 * Author: Kirill Kurakov <xkurak03>
 * Date Created: 
 * Note:
 */
#include "ipkl2l3scan.h"

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
 * @brief Function that print help message
 * 
 * @return void
 */
void print_help(){
    fprintf(stderr, "Usage: %s [-i interface | --interface interface] {-w timeout} [-s ipv4-subnet | -s ipv6-subnet | --subnet ipv4-subnet | --subnet ipv6-subnet]\n", "ipkl2l3scan");
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
                print_help();
                exit(EXIT_SUCCESS);
            case '?':
                fprintf(stderr, "Unknown option: %s\n", argv[optind - 1]);
                break;
            case ':':
                fprintf(stderr, "Missing argument for %s\n", argv[optind - 1]);
                break;
        }
    }

    // If subnet is not specified, does not have sense to run the program
    if(opts->subnet.empty()) {
        fprintf(stderr, "No subnet specified\n");
        print_help();
        exit(EXIT_FAILURE);
    }

    // If no interface is specified, print all active interfaces and exit
    if(opts->interface.empty()) {
        NetworkUtils::print_active_interfaces();
        fprintf(stderr, "No interface specified\n");
        exit(EXIT_FAILURE);
    }

    // If timeout is negative, does not make sense
    if(opts->timeout < 0) {
        fprintf(stderr, "Invalid timeout value\n");
        print_help();
        exit(EXIT_FAILURE);
    }

}

/**
 * @brief Main function
 * 
 * @param argc
 * @param argv
 * 
 * @return int
 */
int main(int argc, char *argv[]) {

    Options opts;

    parse_arguments(&opts, argc, argv);

    signal(SIGINT, interrupt_sniffer);
    signal(SIGQUIT, interrupt_sniffer);
    signal(SIGTERM, interrupt_sniffer);

    NetworkScanner networkScanner(opts.timeout, opts.interface);

    // Run main part of the program
    networkScanner.scanNetwork(opts.subnet);

    return 0;
}
