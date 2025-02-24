# Network Intrusion Detection System (NIDS)

A basic network intrusion detection system implemented in C++ that monitors network traffic for potential security threats and anomalies.

## Features

- Real-time packet capturing and analysis
- Detection of various attack patterns:
  - TCP SYN Flood attacks
  - Broadcast Ping Flood attacks
  - Random Port Connection Flood detection
  - UDP packet monitoring
- Traffic statistics monitoring
- Logging system for alerts and events
- Configurable threshold for anomaly detection

## Prerequisites

- Linux operating system
- libpcap library
- G++ compiler
- Root/sudo privileges
- Basic Knowledge of Networking
- Advance Knowledge of C/C++

## Installation

1. Install the required dependencies:
```bash
sudo apt-get update
sudo apt-get install libpcap-dev
```

2. Clone the repository:
```bash
git clone https://github.com/yourusername/NIDS.git
cd NIDS
```

3. Compile the program:
```bash
g++ -o nids Intru.cpp -lpcap -pthread
```

## Usage

1. Run the program with root privileges:
```bash
sudo ./nids
```

2. Enter the IP address you want to monitor when prompted.

3. The program will start monitoring network traffic and:
   - Display real-time traffic statistics
   - Log alerts to nids_log.txt
   - Show potential security threats

## Logging

The system automatically logs all events to `nids_log.txt`, including:
- Detected attacks
- Traffic statistics
- System errors
- Connection information

## Configuration

You can modify the following parameters in the code:
- `threshold`: Packet count threshold for anomaly detection (default: 100)
- Monitoring intervals
- Port definitions for attack detection

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request
## Acknowledgments

- libpcap library developers
- Network security community
- Contributors and testers

