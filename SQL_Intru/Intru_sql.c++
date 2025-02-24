#include <iostream>
#include <pcap.h>
#include <cstring>
#include <map>
#include <deque>
#include <chrono>
#include <thread>
#include <vector>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <fstream>
#include <sqlite3.h>
#include <iomanip> // For formatted output

using namespace std;

// Global variables
map<string, int> packetCount;
map<string, deque<int>> trafficHistory;
const int historySize = 10; // Number of seconds to calculate moving average
double thresholdMultiplier = 2.0; // Adjust based on network behavior
string targetIP;
ofstream logFile("nids_log.txt");

sqlite3 *db; // SQLite database handle

// Open SQLite database connection
bool openDatabase() {
    if (sqlite3_open("nids_sig.db", &db)) {
        cerr << "Error opening database: " << sqlite3_errmsg(db) << endl;
        return false;
    }
    return true;
}

// Query database for attack signatures and display all details
void checkSignature(const string &protocol, const string &description) {
    string sql = "SELECT attack_name, severity FROM attack_sig WHERE protocol = ? AND description = ?";
    sqlite3_stmt *stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        cerr << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        return;
    }

    sqlite3_bind_text(stmt, 1, protocol.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, description.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        string attackName = (const char *)sqlite3_column_text(stmt, 0);
        string severity = (const char *)sqlite3_column_text(stmt, 1);

        cout << "\n[ALERT] Detected an attack!" << endl;
        cout << "Attack Name: " << attackName << endl;
        cout << "Protocol: " << protocol << endl;
        cout << "Description: " << description << endl;
        cout << "Severity: " << severity << endl;

        logFile << "\n[ALERT] Detected an attack!\n";
        logFile << "Attack Name: " << attackName << "\n";
        logFile << "Protocol: " << protocol << "\n";
        logFile << "Description: " << description << "\n";
        logFile << "Severity: " << severity << "\n";

    } else {
        cout << "[INFO] No matching signature found in the database." << endl;
        logFile << "[INFO] No matching signature found in the database." << endl;
    }

    sqlite3_finalize(stmt);
}

// Callback function for packet processing
void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const int ipHeaderOffset = 14; // Ethernet header size
    const u_char *ipHeader = packet + ipHeaderOffset;

    char srcIP[16], dstIP[16];
    snprintf(srcIP, sizeof(srcIP), "%u.%u.%u.%u", ipHeader[12], ipHeader[13], ipHeader[14], ipHeader[15]);
    snprintf(dstIP, sizeof(dstIP), "%u.%u.%u.%u", ipHeader[16], ipHeader[17], ipHeader[18], ipHeader[19]);

    if (targetIP == srcIP || targetIP == dstIP) {
        if (packet[23] == 1) { // ICMP protocol
            checkSignature("ICMP", "Ping flood attack");
            return;
        }

        if (packet[23] == 17) { // UDP protocol
            checkSignature("UDP", "High-volume UDP packets");
            return;
        }

        if (packet[23] == 6) { // TCP protocol
            if (packet[47] == 0x02) { // SYN flag
                checkSignature("TCP", "SYN flood attack detected");
            }
        }

        packetCount[targetIP]++;
    }
}

// Monitor traffic for anomalies and print statistics
void monitorTraffic() {
    while (true) {
        this_thread::sleep_for(chrono::seconds(1)); // Check every second

        cout << "\n--- Traffic Statistics ---\n";
        logFile << "\n--- Traffic Statistics ---\n";

        for (auto &[ip, count] : packetCount) {
            trafficHistory[ip].push_back(count);
            if (trafficHistory[ip].size() > historySize) {
                trafficHistory[ip].pop_front();
            }

            int sum = 0;
            for (int c : trafficHistory[ip]) {
                sum += c;
            }
            int movingAvg = sum / trafficHistory[ip].size();

            cout << "IP: " << ip << " | Packets: " << count
                 << " | Moving Avg: " << movingAvg << "\n";
            logFile << "IP: " << ip << " | Packets: " << count
                    << " | Moving Avg: " << movingAvg << "\n";

            if (count > movingAvg * thresholdMultiplier) {
                cout << "\n[ALERT] Anomaly detected for IP: " << ip
                     << " | Traffic: " << count
                     << " exceeds " << thresholdMultiplier << "x moving average (" << movingAvg << ")\n";
                logFile << "\n[ALERT] Anomaly detected for IP: " << ip
                        << " | Traffic: " << count
                        << " exceeds " << thresholdMultiplier << "x moving average (" << movingAvg << ")\n";
            }
        }

        packetCount.clear();
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];

    if (!openDatabase()) {
        return 1;
    }

    cout << "Enter the IP address to monitor: ";
    cin >> targetIP;

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

    thread monitorThread(monitorTraffic);

    if (pcap_loop(handle, 0, packetHandler, nullptr) == -1) {
        cerr << "Error capturing packets: " << pcap_geterr(handle) << endl;
        logFile << "Error capturing packets: " << pcap_geterr(handle) << endl;
        return 1;
    }

    monitorThread.join();
    pcap_close(handle);
    sqlite3_close(db);
    logFile.close();
    return 0;
}

