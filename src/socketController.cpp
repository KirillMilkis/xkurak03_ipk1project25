#include "socketController.h"





int SocketController::createRawSocket() {

    int sock = socket(AF_PACKET, SOCK_RAW,  htons(ETH_P_ARP));
    if(sock < 0){
        perror("Socket error");
        exit(1);
    }

    this->raw_socket = sock;

    return sock;

}

int SocketController::createIoctlSocket() {

    int sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if(sock < 0){
        perror("Socket error");
        exit(1);
    }

    this->ioctl_socket = sock;

    return sock;

}

int SocketController::getRawSocket() {
    return this->raw_socket;
}

int SocketController::getIoctlSocket() {
    return this->ioctl_socket;
}

void SocketController::closeRawSocket() {
    close(this->raw_socket);

    this->raw_socket = -1;  
}

void SocketController::closeIoctlSocket() {
    close(this->ioctl_socket);

    this->ioctl_socket = -1;
}