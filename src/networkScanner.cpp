/*
 * File: networkScanner.cpp
 * Author: Kirill Kurakov <xkurak03>
 * Date Created: 
 * Note:
 */
#include "networkScanner.h"

/**
 * @brief Function that scans the network, all subnets and all IPs that were specified
 * 
 * @param subnets Vector of subnets that will be scanned
 * 
 * @return int
 */
int NetworkScanner::scanNetwork(std::vector<std::string> subnets){

    IpManager ipManager(subnets);

    ipManager.printAllSubnets();

    do {
  
        while (ipManager.getNextIp() != nullptr) {
            // Special variable to copy it into the thread
            std::vector<unsigned char> current_ip(ipManager.getCurrentIp(), ipManager.getCurrentIp() + (IpManager::isIPv6(ipManager.getCurrentIpString()) ? 16 : 4));
            // Add new task for the thread that will scan one Ip address
            this->pool.addTask([&, current_ip_copy = std::move(current_ip)]() {
                if(IpManager::isIPv6(ipManager.getCurrentIpString())) {
                    this->scanAdress(AF_INET6, this->ip_mac_map_v6, this->ip_icmp_reply_map_v6, current_ip_copy); // IpV6
                } else {
                    this->scanAdress(AF_INET, this->ip_mac_map_v4, this->ip_icmp_reply_map_v4, current_ip_copy); // IpV4
                }

            });
            // Notify the thread that there is a new task to do
            this->pool.notifyOne();

        }   
        // Start the specific number of threads to avoid overloading the system
        this->pool.start(THREADS_MAX);
        // Wait for all threads, that scan one subnet, to finish
        this->pool.stop();
        
        // Go to scan next subnet
    } while(ipManager.useNextSubnet());

    
    this->printResults(this->ip_mac_map_v4, this->ip_icmp_reply_map_v4, AF_INET);
    this->printResults(this->ip_mac_map_v6, this->ip_icmp_reply_map_v6, AF_INET6);

    return 0;

}

/**
 * @brief Function that processes adress resolution (ARP and NDP) request and response
 * 
 * @param target_ip_char Target IP address
 * @param arpHandler TransportHandler for ARP or NDP
 * @param timeout_ms Timeout in milliseconds
 * 
 * @return bool True if the response was received, false otherwise
 */
bool NetworkScanner::processAR(const unsigned char* target_ip_char, TransportHandler* arpHandler, long timeout_ms) {

    if (arpHandler->SendRequest(target_ip_char, nullptr) == SUCCESS_SENDED) {
        if(arpHandler->ListenToResponce(timeout_ms) == SUCCESS_RECEIVED) {
           return true;
        }
    }
    return false;
}

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
bool NetworkScanner::processICMP(const unsigned char* target_ip_char, std::string target_mac_string, TransportHandler& icmpHandler, long timeout_ms) {

    // Transform target MAC address from string to bytes to use it in the ICMP request
    unsigned char target_mac_char[6];
    if(!NetworkUtils::macStringToBytes(target_mac_string, target_mac_char)){
        return false;
    }

    if (icmpHandler.SendRequest(target_ip_char, target_mac_char) == SUCCESS_SENDED){
        if (icmpHandler.ListenToResponce(timeout_ms) == SUCCESS_RECEIVED) {
           return true;
        } 
    }   

    return false;

}

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
int NetworkScanner::scanAdress(int ip_type, std::map<std::string, std::string>& ip_mac_map, std::map<std::string, bool>& ip_icmp_reply_map, std::vector<unsigned char> current_ip) {

    // Create TransportHandler that will send one request and try to find one response for this request
    // ARP or NDP
    TransportHandler transportHandlerAdrRes(this->interface, this->protocol_rules[ip_type].first, current_ip.data(), nullptr);

    const unsigned char* target_ip_char = current_ip.data();
    
    std::string target_ip_string = NetworkUtils::ipToString(target_ip_char, ip_type);

    // If ARP or NDP response was received, save the MAC address to the map, otherwise save "not found"
    // Use Mutex to avoid memory conflicts
    if (processAR(target_ip_char, &transportHandlerAdrRes, this->timeout_ms)){
        this->pool.lockMutex();
        ip_mac_map[target_ip_string] = transportHandlerAdrRes.GetDestMAC();   //
    } else {
        this->pool.lockMutex();
        ip_mac_map[target_ip_string] = "not found"; 
    }
    this->pool.unlockMutex();

    this->pool.lockMutex();
    std::string target_mac_string = ip_mac_map[target_ip_string];
    this->pool.unlockMutex();

    // If MAC address wasnt found, there is no need to send ICMP request
    if (target_mac_string != "not found"){
        // ICMP or ICMPv6
        TransportHandler transportHandlerIcmp(this->interface, protocol_rules[ip_type].second, current_ip.data(), nullptr);
        // If ICMP response was received, save the result to the map, otherwise save false
        if(processICMP(target_ip_char, target_mac_string, transportHandlerIcmp, this->timeout_ms)){
            this->pool.lockMutex();
            ip_icmp_reply_map[target_ip_string] = true;
        } else {
            this->pool.lockMutex();
            ip_icmp_reply_map[target_ip_string] = false;
        }
        this->pool.unlockMutex();
    
    } else {
        this->pool.lockMutex();
        ip_icmp_reply_map[target_ip_string] = false;
        this->pool.unlockMutex();
    }

    return 0;

}

/**
 * @brief Function that prints the results of the scanning
 * 
 * @param ip_mac_map Map of IP addresses and their MAC addresses
 * @param ip_icmp_reply_map Map of IP addresses and their ICMP response
 * 
 * @return int
 */
int NetworkScanner::printResults(std::map<std::string, std::string> ip_mac_map, std::map<std::string, bool> ip_icmp_reply_map, int ip_type) {

    for (auto& [ip, mac] : ip_mac_map) {
        unsigned char mac_c[6];
        // |IPaddr arp|
        if(ip_type == AF_INET){
            printf("%s arp ", ip.c_str());
        } else if(ip_type == AF_INET6){
            printf("%s ndp ", ip.c_str());
        }
    
        // |(MAC address)| or |FAIL|
        if(mac != "not found"){
            sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac_c[0], &mac_c[1], &mac_c[2], &mac_c[3], &mac_c[4], &mac_c[5]);
            printf("(%02x-%02x-%02x-%02x-%02x-%02x)", mac_c[0], mac_c[1], mac_c[2], mac_c[3], mac_c[4], mac_c[5]);
        } else {
            printf("FAIL");
        }
        // |, or icmp OK| or |, icmp FAIL|
        printf(", ");
        if(ip_icmp_reply_map[ip]){
            if(ip_type == AF_INET){
                printf("icmpv4 OK\n");
            } else if(ip_type == AF_INET6){
                printf("icmpv6 OK\n");
            }
        } else {
            if(ip_type == AF_INET){
                printf("icmpv4 FAIL\n");
            } else if(ip_type == AF_INET6){
                printf("icmpv6 FAIL\n");
            }
        }

    }

    return 0;
}
