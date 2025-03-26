/*
 * File: transportHandler.h
 * Author: Kirill Kurakov <xkurak03>
 * Date Created: 
 * Note:
 */
#ifndef TRANSPORTHANDLER_H
#define TRANSPORTHANDLER_H

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <netinet/ip.h>
#include "networkUtils.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <linux/if_ether.h>
#include <cstring>

#include "headerBuilder.h"

#define SUCCESS_SENDED 3
#define SUCCESS_RECEIVED 4
#define NS_HEADER_LEN 24

/**
 * @brief Class that is responsible for sending and receiving packets by the socket
 */
class TransportHandler {
    private:
        int sock;
        unsigned char* buffer;
        const std::string iface;
        int protocol;
        struct ifreq ifr;
        NetworkUtils networkUtils;

        unsigned char src_mac[6];  // Source MAC
        unsigned char src_ip[4];  // Source IP

        unsigned char dst_mac[6];  // Destination MAC
        unsigned char dst_ip[4];  // Destination IP

        unsigned char dst_ip6[16];  // Destination IP


    public:

        /**
         * @brief Construct a new Transport Handler object
         * 
         * @param iface Interface name
         * @param protocol Protocol
         * @param ipaddr Destination IP address
         * @param dst_mac Destination MAC address
         */
        TransportHandler(const std::string& iface, int protocol, const unsigned char* ipaddr, const unsigned char* dst_mac) : iface(iface), protocol(protocol) {

            memset(this->ifr.ifr_name, 0, IFNAMSIZ);
            memset(this->src_mac,0, 6);
            memset(this->src_ip, 0, 4);
            memset(this->dst_mac, 0, 6);
            memset(this->dst_ip, 0, 4);

            this->sock = -1;

            iface.copy(ifr.ifr_name, IFNAMSIZ);

            buffer = (unsigned char*)malloc(sizeof(unsigned char) * ETH_FRAME_LEN);
            if(buffer == NULL) {
                perror("malloc() failed");
                exit(EXIT_FAILURE);

            }

            memcpy(this->src_ip, this->networkUtils.getIP(iface.c_str(), AF_INET), 4);
            memcpy(this->src_mac, this->networkUtils.getMAC(&ifr), 6);

            // Use different type of IP address based on the protocol
            if(this->protocol == ARP || this->protocol == ICMP) {
                memcpy(this->dst_ip, ipaddr, 4);
            } else if(this->protocol == ICMPv6 || this->protocol == NDP) {
                memcpy(this->dst_ip6, ipaddr, 16);
            }

            if(dst_mac != nullptr) {
                memcpy(this->dst_mac, dst_mac, 6);
            }


        }

        /**
         * @brief Send request to the network with the specific protocol
         * 
         * @param ipaddr Destination IP address
         * @param dst_mac Destination MAC address
         * 
         * @return int
         */
        int SendRequest(const unsigned char* ipaddr, const unsigned char* dst_mac);

        /**
         * @brief Listen to the response from the network
         * 
         * @param timeout_ms Timeout in milliseconds
         * 
         * @return int
         */
        int ListenToResponce(long int timeout_ms);

        /**
         * @brief Test if the ARP response is valid
         * 
         * @param buffer Buffer with the response
         * 
         * @return bool True if the response is valid, false otherwise
         */
        bool testArpResponse(const unsigned char* buffer);

        /**
         * @brief Test if the ICMP response is valid
         * 
         * @param buffer Buffer with the response
         * 
         * @return bool True if the response is valid, false otherwise
         */
        bool testICMPResponse(const unsigned char* buffer);

        /**
         * @brief Test if the NDP response is valid
         * 
         * @param buffer Buffer with the response
         * 
         * @return bool True if the response is valid, false otherwise
         */
        bool testNDPResponse(const unsigned char* buffer);

        /**
         * @brief Test if the ICMPv6 response is valid
         * 
         * @param buffer Buffer with the response
         * 
         * @return bool True if the response is valid, false otherwise
         */
        bool testICMPv6Response(const unsigned char* buffer);

        std::string GetDestMAC();

        ~TransportHandler() {
            if(this->buffer != NULL) {
                free(this->buffer);
            }
            if(this->sock > 0) {
                close(this->sock);
            }
        }

};


#endif // TRASPORTHANDLER_H