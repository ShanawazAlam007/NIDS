#include <iostream>
#include <pcap.h>
#include <cstring>
#include <map>
#include <chrono>
#include <thread>
#include <vector>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <fstream>

using namespace std;

// Global variables
map<string, int> packetCount; // Track packets per IP
int threshold = 100; // Example anomaly threshold (packets per second)
string targetIP; // IP address to monitor
vector<int> timePoints; // Time points for graphing
vector<int> packetCounts; // Packet counts for graphing
ofstream logFile("nids_log.txt"); // Log file

// Callback function for packet processing
void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Extract IP addresses (assuming Ethernet + IPv4)
    const int ipHeaderOffset = 14; // Ethernet header size
    const u_char *ipHeader = packet + ipHeaderOffset;

    char srcIP[16], dstIP[16];
    snprintf(srcIP, sizeof(srcIP), "%u.%u.%u.%u", ipHeader[12], ipHeader[13], ipHeader[14], ipHeader[15]);
    snprintf(dstIP, sizeof(dstIP), "%u.%u.%u.%u", ipHeader[16], ipHeader[17], ipHeader[18], ipHeader[19]);

    // Check if the packet is related to the target IP
    if (targetIP == srcIP || targetIP == dstIP) {
        // Check if this is an ICMP packet (Ping)
        if (packet[23] == 1) {  // ICMP protocol
            if (strcmp(dstIP, "255.255.255.255") == 0) { // Check for broadcast ping flood
                cout << "[ALERT] Broadcast Ping Flood detected from " << srcIP << endl;
                logFile << "[ALERT] Broadcast Ping Flood detected from " << srcIP << endl;
            } else {
                cout << "Ignoring ICMP Echo Request from " << srcIP << endl;
                logFile << "Ignoring ICMP Echo Request from " << srcIP << endl;
            }
            return;  // Ignore ping packets to prevent flooding detection
        }

        // Check if this is a UDP packet
        if (packet[23] == 17) {  // UDP protocol is 17
            cout << "Ignoring UDP packet from " << srcIP << endl;
            logFile << "Ignoring UDP packet from " << srcIP << endl;
            return;  // Ignore UDP packets to prevent flood detection
        }

        // Check if this is a TCP SYN packet (SYN Flood)
        if (packet[23] == 6) {  // TCP protocol is 6
            if (packet[47] == 0x02) {  // SYN flag (0x02)
                cout << "Potential TCP SYN Flood detected from " << srcIP << endl;
                logFile << "Potential TCP SYN Flood detected from " << srcIP << endl;
            }
            // Check for Random Port Connection Flood
            const struct tcphdr *tcpHeader = (struct tcphdr *)(packet + ipHeaderOffset + 20);
            if (tcpHeader->dest != 80 && tcpHeader->dest != 443) { // Random ports other than HTTP/HTTPS
                cout << "[ALERT] Random Port Connection Flood detected from " << srcIP << endl;
                logFile << "[ALERT] Random Port Connection Flood detected from " << srcIP << endl;
            }
        }
        
        packetCount[targetIP]++;
    }
}

// Monitor traffic for anomalies and print statistics
void monitorTraffic() {
    int timeElapsed = 0; // Track time

    while (true) {
        this_thread::sleep_for(chrono::seconds(1)); // Check every second

        int totalPackets = 0;
        cout << "--- Traffic Statistics ---\n";
        logFile << "--- Traffic Statistics ---\n";
        for (auto &[ip, count] : packetCount) {
            cout << "IP: " << ip << " | Packets: " << count << "\n";
            logFile << "IP: " << ip << " | Packets: " << count << "\n";
            totalPackets += count;
            if (count > threshold) {
                cout << "[ALERT] Anomaly detected for IP: " << ip << "\n";
                logFile << "[ALERT] Anomaly detected for IP: " << ip << "\n";
            }
        }

        timeElapsed++;
        packetCount.clear(); 
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Ask user for the IP address to monitor
    cout << "Enter the IP address to monitor: ";
    cin >> targetIP;

    // Open the default device for live capture
    pcap_if_t *allDevs;
    if (pcap_findalldevs(&allDevs, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << endl;
        logFile << "Error finding devices: " << errbuf << endl;
        return 1;
    }

    char *dev = allDevs->name;
    cout << "Using device: " << dev << endl;
    logFile << "Using device: " << dev << endl;

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "Error opening device: " << errbuf << endl;
        logFile << "Error opening device: " << errbuf << endl;
        return 1;
    }

    // Start the monitoring thread
    thread monitorThread(monitorTraffic);

    // Capture packets
    if (pcap_loop(handle, 0, packetHandler, nullptr) == -1) {
        cerr << "Error capturing packets: " << pcap_geterr(handle) << endl;
        logFile << "Error capturing packets: " << pcap_geterr(handle) << endl;
        return 1;
    }

    // Cleanup
    monitorThread.join();
    pcap_close(handle);
    pcap_freealldevs(allDevs);
    logFile.close();
    return 0;
}

