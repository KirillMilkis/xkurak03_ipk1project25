#ifndef FRAMECONTROLLER_H
#define FRAMECONTROLLER_H

#include <string>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include "packetSender.h"
#include "ipManager.h"

class FrameController {
    public:
        FrameController(std::vector<std::string> subnet):
            subnet(subnet) {}

        void manageARP();

        void manageICMP();


    private:
        std::vector<std::string> subnet;

};

#endif // FRAMECONTROLLER_H