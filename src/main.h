
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
#include <pcap.h>
#include <thread>
#include <future>
#include <chrono>
#include <atomic>

#include <vector>

#include "transportHandler.h"

// https://cfengine.com/blog/2021/optional-arguments-with-getopt-long/
#define OPTIONAL_ARGUMENT_IS_PRESENT \
    ((optarg == NULL && optind < argc && argv[optind][0] != '-') \
     ? (bool) (optarg = argv[optind++]) \
     : (optarg != NULL))


typedef struct eth_hdr{
    unsigned char dest[6];
    unsigned char src[6];
    unsigned short type;
} ETH_HDR;



#endif // MAIN_H