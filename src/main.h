
#ifndef MAIN_H
#define MAIN_H

#include <map>
#include "ipManager.h"
#include "transportHandler.h"

typedef struct eth_hdr{
    unsigned char dest[6];
    unsigned char src[6];
    unsigned short type;
} ETH_HDR;



#endif // MAIN_H