/*
 * File: ipkl2l3scan.h
 * Author: Kirill Kurakov <xkurak03>
 * Date Created: 
 * Note:
 */
#ifndef IPKL2L3SCAN_H
#define IPKL2L3SCAN_H

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
 * @brief Function that print help message
 * 
 * @return void
 */
void print_help();

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


#endif // IPKL2L3SCAN_H