#include <string>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream> 
#include <sstream>
#include <bitset>

#include "frameController.h"


void FrameController::manageARP() {

    PacketSender packetSender;

    IpManager ipManager(subnet[0]);

    packetSender.SendARP(ipManager.getNextIp());
    

}





