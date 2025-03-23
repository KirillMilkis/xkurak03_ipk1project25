
#ifndef MAIN_H
#define MAIN_H

#include <map>
#include "arpHandler.h"
#include "ipManager.h"

typedef struct eth_hdr{
    unsigned char dest[6];
    unsigned char src[6];
    unsigned short type;
} ETH_HDR;



#endif // MAIN_H