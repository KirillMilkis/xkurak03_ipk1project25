
#ifndef MAIN_H
#define MAIN_H

#include <map>
#include "ipManager.h"
#include "transportHandler.h"

#define no_argument 0
#define required_argument 1
#define optional_argument 2

#define SUCCESS_SENDED 3

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <iostream>
#include <libnet.h>
#include <vector>

#include "transportHandler.h"
#include "networkScanner.h"
//  https://cfengine.com/blog/2021/optional-arguments-with-getopt-long/

// #define OPTIONAL_ARGUMENT_IS_PRESENT \
//     ((optarg == NULL && optind < argc && argv[optind][0] != '-') \
//      ? (bool) (optarg = argv[optind++]) \
//      : (optarg != NULL))

/**
 * @brief Structure to process program oiptions in getopt_long function
 */
static struct option long_options[] = {
    {"interface", optional_argument, NULL, 'i'},
    {"wait", optional_argument, NULL, 'w'},
    {"subnet", optional_argument, NULL, 's'},
    {"help", no_argument, NULL, 'h'},
    {0, 0, 0, 0}
};

/**
 * @brief Structure for storing program options
 */
typedef struct options{
    std::string interface;
    long int timeout;
    std::vector<std::string> subnet;
} Options;

/**
 * @brief Function that handle different interrupt signals like Ctrl + C
 * 
 * @param signum 
 * 
 * @return void
 */
void interrupt_sniffer(int signum);

/**
 * @brief Function that parse arguments from command line
 * 
 * @param opts
 * @param argc
 * @param argv
 * 
 * @return void
 */
void parse_arguments(Options* opts, int argc, char *argv[]);

/**
 * @brief Main function
 * 
 * @param argc
 * @param argv
 * 
 * @return int
 */
int main(int argc, char *argv[]);


#endif // MAIN_H