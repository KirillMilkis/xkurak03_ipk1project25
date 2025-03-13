#include <string>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream> 
#include <sstream>
#include <bitset>
#include <malloc.h>
#include <thread>

#include "frameController.h"
#define SUCCESS_SENDED 1


void FrameController::manageARP() {

    PacketSender packetSender;

    unsigned char* ipaddr = (unsigned char*)malloc(sizeof(unsigned char) * 4);

    IpManager ipManager(subnet[0]);

    ipManager.getNextIp(ipaddr);

    printf("ipaddr: %s\n", ipaddr);
    while(ipManager.getNextIp(ipaddr) != NULL) {
        printf("ipaddr: %s\n", ipaddr);
        if (packetSender.SendARP(ipManager.getNextIp(ipaddr)) == SUCCESS_SENDED){
            while(1){
                length 
            }
        } else {
            printf("ARP packet was not sent\n");
        }
    }
    if packetSender.SendARP(ipManager.getNextIp(ipaddr)) == SUCCESS_SENDED {
        
    } else {
        printf("ARP packet was not sent\n");
    }
    

}





