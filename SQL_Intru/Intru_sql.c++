#include <iostream>
#include <pcap.h>
#include <sqlite3.h>
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
map<string, int> packetCount;
map<string, pair<int, string>> attackSignatures; // Store known attacks with threshold from DB
int baseTrafficRate = 20; // Base traffic rate, dynamically adjusted
int timeWindow = 5; // Time window in seconds for sustained attack check
string targetIP;
sqlite3 *db;
ofstream logFile("nids_log.txt");
bool attackDetected = false;

// Function to check database connection
bool checkDatabaseConnection() {
    if (sqlite3_open("nids_sig.db", &db) != SQLITE_OK) {
        cerr << "Error opening database: " << sqlite3_errmsg(db) << endl;
        return false;
    }
    cout << "Database connected successfully." << endl;
    return true;
}

// Function to fetch attack signatures and thresholds from SQLite3
void loadAttackSignatures() {
    string sql = "SELECT protocol, signature, threshold FROM attack_sig;";
    sqlite3_stmt *stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        cerr << "Error fetching attack signatures: " << sqlite3_errmsg(db) << endl;
        return;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        string protocol = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        string signature = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        int threshold = sqlite3_column_int(stmt, 2);
        attackSignatures[protocol] = make_pair(threshold, signature);
    }

    sqlite3_finalize(stmt);
}

// Packet handler function
void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const int ipHeaderOffset = 14;
    const u_char *ipHeader = packet + ipHeaderOffset;

    char srcIP[16], dstIP[16];
    snprintf(srcIP, sizeof(srcIP), "%u.%u.%u.%u", ipHeader[12], ipHeader[13], ipHeader[14], ipHeader[15]);
    snprintf(dstIP, sizeof(dstIP), "%u.%u.%u.%u", ipHeader[16], ipHeader[17], ipHeader[18], ipHeader[19]);

    // Monitor only the target IP
    if (targetIP != srcIP && targetIP != dstIP) {
        return;
    }

    string protocol;
    string detectedSignature = "Unknown";
    int threshold = baseTrafficRate;

    if (packet[23] == 1) {
        protocol = "ICMP";
    } else if (packet[23] == 17) {
        protocol = "UDP";
    } else if (packet[23] == 6) {
        protocol = "TCP";
    }

    if (attackSignatures.find(protocol) != attackSignatures.end()) {
        threshold = attackSignatures[protocol].first;
        detectedSignature = attackSignatures[protocol].second;
    }

    packetCount[srcIP]++;
    
    if (packetCount[srcIP] > threshold) {
        attackDetected = true;
        cout << "[ALERT] " << detectedSignature << " detected from " << srcIP << " | Packets: " << packetCount[srcIP] << endl;
        logFile << "[ALERT] " << detectedSignature << " detected from " << srcIP << " | Packets: " << packetCount[srcIP] << endl;
    }
}

// Monitor traffic and detect anomalies dynamically
void monitorTraffic() {
    while (true) {
        this_thread::sleep_for(chrono::seconds(timeWindow));
        
        if (packetCount[targetIP] > baseTrafficRate * 1.5) { // Dynamic threshold check
            attackDetected = true;
            cout << "[ALERT] Potential attack detected for IP: " << targetIP << " | Packets: " << packetCount[targetIP] << "\n";
            logFile << "[ALERT] Potential attack detected for IP: " << targetIP << " | Packets: " << packetCount[targetIP] << "\n";
        } else if (attackDetected) {
            attackDetected = false;
            cout << "Network traffic is normal." << endl;
            logFile << "Network traffic is normal." << endl;
        }
        packetCount.clear(); // Reset count periodically
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Check database connection
    if (!checkDatabaseConnection()) {
        return 1;
    }

    // Load attack signatures from database
    loadAttackSignatures();

    // Ask user for the IP address to monitor
    cout << "Enter the IP address to monitor: ";
    cin >> targetIP;

    // Open default network device for capture
    pcap_if_t *allDevs;
    if (pcap_findalldevs(&allDevs, errbuf) == -1 || allDevs == nullptr) {
        cerr << "Error finding devices: " << errbuf << endl;
        return 1;
    }

    char *dev = allDevs->name;
    if (!dev) {
        cerr << "No valid network device found." << endl;
        return 1;
    }
    cout << "Using device: " << dev << endl;

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "Error opening device: " << errbuf << endl;
        return 1;
    }

    // Start the monitoring thread
    thread monitorThread(monitorTraffic);
    monitorThread.detach();

    // Capture packets
    if (pcap_loop(handle, 0, packetHandler, nullptr) == -1) {
        cerr << "Error capturing packets: " << pcap_geterr(handle) << endl;
    }

    // Cleanup
    pcap_close(handle);
    sqlite3_close(db);
    logFile.close();
    return 0;
}