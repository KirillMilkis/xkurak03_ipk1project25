/*
 * File: networkUtils.h
 * Author: Kirill Kurakov <xkurak03>
 * Date Created: 
 * Note:
 */
#ifndef NETWORKUTILS_H
#define NETWORKUTILS_H

#include <iostream>
#include <array>
#include <pcap.h>
#include <cstring>
#include <vector>
#include <pcap.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>  
#include <string>

#define ARP 1
#define ICMP 2
#define ICMPv6 4
#define NDP 3

#define BUFSIZE 100
#define ARP_HDR_LEN 28
#define IP4_HDR_LEN 20
#define ICMP_HDR_LEN 8
#define ICMP6_HDR_LEN 32
#define IP6_HDR_LEN 40

/**
 * @brief Structure for Ethernet header
 */
typedef struct eth_hdr{
    unsigned char dest[6];
    unsigned char src[6];
    unsigned short type;
} ETH_HDR;

/**
 * @brief Class providing various network-related functionalities, usually as static methods.
 */
class NetworkUtils {
    private:
        static unsigned char* ip_addrv4; // IPv4 address source address
        static unsigned char* ip_addrv6; // IPv6 address source address
        static unsigned char* mac_addr; // MAC source address

    public:

    /**
     * @brief Get MAC address of the interface
     * 
     * @param ifr Interface request structure
     * 
     * @return unsigned char* MAC address
     */
    static unsigned char* getMAC(struct ifreq* ifr);


    /**
     * @brief Get IP address of the interface
     * 
     * @param iface Interface name
     * @param family Address family
     * 
     * @return unsigned char* IP address
     */
    static unsigned char* getIP(const char* iface, int family);

    /**
     * @brief Calculate checksum of the header
     * 
     * @param b Packet
     * @param len Length of the header
     * 
     * @return unsigned short Checksum
     */
    static unsigned short checksum(void *b, int len);

    /**
     * @brief Convert MAC address to string
     * 
     * @param mac MAC address as unsigned char*
     * 
     * @return std::string MAC address as string
     */
    static std::string macToString(unsigned char* mac);

    /**
     * @brief Convert IP address to string
     * 
     * @param ip IP address as unsigned char*
     * @param family Address family to determine the IP version
     * 
     * @return std::string IP address as string
     */
    static std::string ipToString(const unsigned char* ip, int family);

    /**
     * @brief Convert MAC address string to bytes
     * 
     * @param macStr MAC address as string
     * @param macBytes MAC address as unsigned char*
     * 
     * @return bool True if conversion was successful, false otherwise
     */
    static bool macStringToBytes(const std::string& macStr, unsigned char macBytes[6]);

    /**
     * @brief Get all interfaces
     * 
     * @return pcap_if_t* All interfaces
     */
    static pcap_if_t* get_interfaces();
    
    /**
     * @brief Print all active interfaces
     * 
     * @return int 0 if successful
     */
    static void print_active_interfaces();

};



#endif // NETWORKUTILS_H