# IPK - DELTA: L2/L3 Scanner

**Author**: Kirill Kurakov. VUT login: xkurak03

## Table of Contents

- [Theory](#theory)
- [Scanning Techniques](#scanning-techniques)
- [Implementation](#implementation)
  - [UML Class Diagram](#uml-class-diagram)
  - [Diagram Description](#diagram-description)
- [Testing](#testing)
  - [Test 1: Scanning IPv4 Subnet](#test-1-scanning-ipv4-subnet)
  - [Test 2: Scanning IPv6 Subnet](#test-2-scanning-ipv6-subnet)
  - [Test 3: Very Big Subnet](#test-3-very-big-subnet)
- [How to Run `ipk-l2l3-scan`](#HowToRun)
- [Bibliography](#Bibliografy)

## Theory

L2/L3 Scanner is a network scanning tool designed to discover active hosts on a network at both Layer 2 (Data Link Layer) and Layer 3 (Network Layer) of the OSI model. It performs network discovery using ARP (Address Resolution Protocol) and NDP (Neighbor Discovery Protocol) for MAC address resolution, as well as ICMP (Internet Control Message Protocol) for reachability testing.

This tool is useful for network administrators and security professionals who need to analyze network topology, detect active devices, and troubleshoot connectivity issues.

## Scanning Techniques

1. **MAC Address Discovery (Layer 2)**  
    - **ARP (Address Resolution Protocol):**
      - Used to discover MAC addresses of devices on an IPv4 network.
      - The scanner sends an ARP request and listens for ARP replies to determine the MAC address associated with a given IP.
    - **NDP (Neighbor Discovery Protocol) for IPv6:**
      - The IPv6 equivalent of ARP.
      - Uses Neighbor Solicitation and Neighbor Advertisement messages to resolve MAC addresses.
      
2. **Host Availability Check (Layer 3)**  
    - **ICMP Echo Requests (Ping):**
      - Used to determine if a host is reachable.
      - If no response is received, the device may be offline, unreachable, or configured to block ICMP traffic.

## Implementation

### UML Class Diagram

![UML Class Diagram](UML_class.png)

### Diagram Description

Scanner was implemented using the principles of Object Oriented Programming. It was possible to create separate independent classes that have their own tasks and meaning of life. The Builder pattern was also applied (class **HeaderBuilder**).


- The main class is **NetworkScanner**. The program starts with this class, which contains methods like `scanNetwork()`, `scanAddress()`, `processArp()`, etc. These methods are responsible for obtaining IP addresses for further communication (Request-Response) and assigning a new thread to each communication process, improving execution speed. This class also constructs and prints final output tables containing MAC addresses for specific IPs (when communication is successful) and IP addresses with ICMP request results.
  
- The **IpManager** class provides methods for navigating between different IP addresses and subnets. The program also uses the `printAllSubnets()` method to display subnets retrieved from the runtime options. It ensures the program does not skip over subnets and verifies that IP addresses are correctly formatted.

- The **TransportHandler** class is responsible for opening a socket and sending frames/packets to the destination IP address. It uses the **HeaderBuilder** class to construct the necessary headers and listens for responses using the `ListenToResponse()` method. The class verifies that received packets/frames match the original request.

- The **HeaderBuilder** class helps create and configure various headers for different types of packets and frames, following the Object-Oriented Programming (OOP) Builder pattern.

- **HeaderBuilder**, **TransportHandler**, and **NetworkScanner** rely on the **NetworkUtils** class to retrieve essential network values (e.g., source IP, source MAC). This avoids unnecessary data transfer between classes.

- The **ThreadPool** class is responsible for creating and running threads, ensuring that only a limited number of threads run simultaneously. It includes mutex methods to control access to shared memory.

## Testing

The program was tested on the `IPK25_Ubuntu24` virtual machine. Since it is a virtual machine, it has local (link-local) addresses for the virtual gateway and the VM itself. The following addresses were obtained by executing the `ip -X neigh show` command in the terminal. Communication with these addresses will be successful in the next tests.
```
(nix:nix-shell-env) ipk@ipk25:~/ipk1project/xkurak03_ipk1project25$ ip -6 neigh show
fd00::2 dev enp0s3 lladdr 52:56:00:00:00:02 router STALE 
fe80::2 dev enp0s3 lladdr 52:56:00:00:00:02 router DELAY 

(nix:nix-shell-env) ipk@ipk25:~/ipk1project/xkurak03_ipk1project25$ ip -4 neigh show
10.0.2.2 dev enp0s3 lladdr 52:55:0a:00:02:02 REACHABLE 
10.0.2.3 dev enp0s3 lladdr 52:55:0a:00:02:03 REACHABLE 
```

### Test 1: Scanning a Small IPv4 Subnet

#### Command Used:

```
sudo ./ipk-l2l3-scan -i enp0s3 -w 1000 -s 10.0.2.2/29
```

#### Results:

```
Scanning ranges:
10.0.2.2 6

10.0.2.1 arp FAIL, icmp FAIL
10.0.2.2 arp (52-55-0a-00-02-02), icmp OK
10.0.2.3 arp (52-55-0a-00-02-03), icmp OK
10.0.2.4 arp FAIL, icmp FAIL
10.0.2.5 arp FAIL, icmp FAIL
10.0.2.6 arp FAIL, icmp FAIL
```

![Wireshark Screenshot](Wireshark1.png)

#### Analysis:

- The program successfully scanned the subnet **10.0.2.2/29**, which consists of **6 usable addresses** (excluding network and broadcast addresses).
- Out of the 6 possible addresses, **2 devices responded** (10.0.2.2 and 10.0.2.3) via both **ARP and ICMP**. The presence of these addresses on the VM local network has been shown above.
- The remaining addresses did not respond to ARP or ICMP requests, indicating no active devices at those IPs.



---

### Test 2: Scanning an IPv6 Subnet

#### Command Used:

```
sudo ./ipk-l2l3-scan -i enp0s3 -w 1000 -s fe80::2/123
```

#### Results:

```
Scanning ranges:
fe80::2 32

fe80:: ndp FAIL, icmp FAIL
fe80::1 ndp FAIL, icmp FAIL
...
fe80::2 ndp (52-56-00-00-00-02), icmp OK
fe80::3 ndp (52-56-00-00-00-03), icmp OK
...
fe80::1f ndp FAIL, icmp FAIL
```

![Wireshark Screenshot](Wireshark2.png)

#### Analysis:

- The scan covered **32 possible addresses** (IPv6 does not reserve addresses for network or broadcast purposes).
- Two devices (fe80::2 and fe80::3) responded via **NDP (Neighbor Discovery Protocol)** and **ICMPv6**.
- The rest of the scanned addresses did not respond, indicating no active devices at those IPs.
- In IPv6, all communication related to host discovery occurs through **ICMPv6**, with **NDP handling address resolution**.



---

### Test 3: Scanning a Large IPv4 Subnet

#### Command Used:

```
sudo ./ipk-l2l3-scan -i enp0s3 -w 1 -s 10.0.2.2/22
```

#### Results (Partial Output):

```
Scanning ranges:
10.0.2.2 1022

10.0.0.1 arp FAIL, icmp FAIL
10.0.0.10 arp FAIL, icmp FAIL
...
10.0.2.3 arp (52-55-0a-00-02-03), icmp OK
...
10.0.3.99 arp FAIL, icmp FAIL
```

#### Analysis:

- This test scanned a much **larger subnet** (**/22**, which contains **1022 usable IPs**).
- Due to the wide range, most addresses **did not respond**.
- Only **one active device** was found at **10.0.2.3**, which successfully responded to both **ARP and ICMP**.
- The test confirms that the scanner efficiently handles large subnets, though scanning such a wide range takes significantly more time.

---

### Conclusion:

- The scanner correctly identifies **active hosts** in both **IPv4 and IPv6 subnets**.
- The tool effectively handles **small and large subnets**, providing accurate results.
- **Wireshark captures confirm** that all communication follows expected network protocols.

## How to Run `ipk-l2l3-scan`

### Basic Usage
```sh
./ipk-l2l3-scan [-i interface | --interface interface] {-w timeout} [-s ipv4-subnet | -s ipv6-subnet | --subnet ipv4-subnet | --subnet ipv6-subnet]
./ipk-l2l3-scan --help
./ipk-l2l3-scan --interface
./ipk-l2l3-scan
```

### Arguments

| Argument | Description |
|----------|-------------|
| `-h`, `--help` | Displays usage instructions and exits. |
| `-i interface`, `--interface interface` | Specifies a network interface to scan through. If omitted, a list of active interfaces is printed. |
| `-w timeout`, `--wait timeout` | Sets the timeout in milliseconds for a response per scan. Default is `5000ms`. |
| `-s subnet`, `--subnet subnet` | Specifies an IPv4 or IPv6 subnet to scan. Can be used multiple times for multiple subnets. |

### Example Commands

1. **Display Help**
   ```sh
   ./ipk-l2l3-scan --help
   ```
2. **List Available Interfaces**
   ```sh
   ./ipk-l2l3-scan --interface
   ```
3. **Scan an IPv4 Subnet**
   ```sh
   sudo ./ipk-l2l3-scan -i eth0 -s 192.168.1.0/24
   ```
4. **Scan Multiple Subnets**
   ```sh
   sudo ./ipk-l2l3-scan -i eth0 -s 192.168.1.0/24 -s fd00:cafe:0000:face::0/120
   ```
## Extra Functionality

You can not speciffy netwrok mask in the --subnet argument and program will scan a single IP address:
```sh
sudo ./ipk-l2l3-scan -i enp0s3 -w 3000 -s 192.168.1.10
```

```sh
sudo ./ipk-l2l3-scan -i enp0s3 -w 3000 -s fd00:cafe:0000:face::0
```

## Bibliography

Below is a list of references and sources used in this project.

1. **RFC 792**: Internet Control Message Protocol, 1981. Online. Request for Comments. Internet Engineering Task Force. [Accessed 26 March 2025].

2. **GUPTA, Mukesh** and **CONTA, Alex**, 2006. RFC 4443: Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6) Specification. Online. Request for Comments. Internet Engineering Task Force. [Accessed 26 March 2025].

3. **Project Repository**: Delta Project - Git Repository. [Accessed 26 March 2025]. Available at: [https://git.fit.vutbr.cz/NESFIT/IPK-Projects/src/branch/master/Project_1/delta](https://git.fit.vutbr.cz/NESFIT/IPK-Projects/src/branch/master/Project_1/delta)

4. **GEEKSFORGEEKS**: Multithreading in C++. [Accessed 26 March 2025]. Available at: [https://www.geeksforgeeks.org/multithreading-in-cpp/](https://www.geeksforgeeks.org/multithreading-in-cpp/)

5. **FIT VUT Course**: IPK - FIT VUT. [Accessed 26 March 2025]. Available at: [https://www.fit.vut.cz/study/course/280936/](https://www.fit.vut.cz/study/course/280936/)




