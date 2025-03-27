/*
 * File: networkScanner.h
 * Author: Kirill Kurakov <xkurak03>
 * Date Created: XX.03.2025
 * Note:
 */
#include "ipManager.h"
#include "threadPool.h"
#include "transportHandler.h"
#include "networkUtils.h"
// Max number of threads in one time
#define THREADS_MAX 50

#include <sys/socket.h> // For AF_INET and AF_INET6
/**
 * @brief Main class of the program that manage what ip adresses will be scanned
 */
class NetworkScanner{

    public:

    /**
     * @brief Construct a new Network Scanner object
     * 
     * @param timeout_ms Timeout in milliseconds
     * @param interface Interface name
     */
    NetworkScanner(int timeout_ms, std::string interface) : timeout_ms(timeout_ms), interface(interface) {}

    /**
     * @brief Function that scans the network, all subnets and all IPs that were specified
     * 
     * @param subnets Vector of subnets that will be scanned
     * 
     * @return int
     */
    int scanNetwork(std::vector<std::string> subnets);

    private:

    int timeout_ms;
    std::string interface;
    ThreadPool pool;

    std::map<std::string, std::string> ip_mac_map_v4; // IpV4 address, MAC address
    std::map<std::string, std::string> ip_mac_map_v6; // IpV6 address, MAC address
    std::map<std::string, bool> ip_icmp_reply_map_v4; // IpV4 address, ICMP response
    std::map<std::string, bool> ip_icmp_reply_map_v6; // IpV6 address, ICMP response

    // Rules what protocols to use for IpV4 and IpV6
    std::map<uint8_t, std::pair<uint8_t, uint8_t>> protocol_rules = {
        {AF_INET, {ARP, ICMP}},
        {AF_INET6, {NDP, ICMPv6}},
    };
    

    /**
     * @brief Function that processes adress resolution (ARP and NDP) request and response
     * 
     * @param target_ip_char Target IP address
     * @param arpHandler TransportHandler for ARP or NDP
     * @param timeout_ms Timeout in milliseconds
     * 
     * @return bool True if the response was received, false otherwise
     */
    bool processAR(const unsigned char* target_ip_char, TransportHandler* arpHandler, long timeout_ms);

    /**
     * @brief Function that processes ICMP request and response
     * 
     * @param target_ip_char Target IP address
     * @param target_mac_string Target MAC address
     * @param icmpHandler TransportHandler for ICMP
     * @param timeout_ms Timeout in milliseconds
     * 
     * @return bool True if the response was received, false otherwise
     */
    bool processICMP(const unsigned char* target_ip_char, std::string target_mac_string, TransportHandler& icmpHandler, long timeout_ms);

    /**
     * @brief Function that scans one IP address
     * 
     * @param ip_type Type of IP address (AF_INET or AF_INET6)
     * @param ip_mac_map Map of IP addresses and their MAC addresses
     * @param ip_icmp_reply_map Map of IP addresses and their ICMP response
     * @param current_ip Current IP address
     * 
     * @return int
     */
    int scanAdress(int ip_type, std::map<std::string, std::string>& ip_mac_map, std::map<std::string, bool>& ip_icmp_reply_map, std::vector<unsigned char> current_ip);

    /**
     * @brief Function that prints the results of the scanning
     * 
     * @param ip_mac_map Map of IP addresses and their MAC addresses
     * @param ip_icmp_reply_map Map of IP addresses and their ICMP response
     * 
     * @return int
     */
    int printResults(std::map<std::string, std::string> ip_mac_map, std::map<std::string, bool> ip_icmp_reply_map, int ip_type);

};