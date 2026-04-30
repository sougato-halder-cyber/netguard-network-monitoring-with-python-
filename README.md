# 🛡️ NetGuard - Advanced Network Monitoring Tool

A high-end, production-ready network monitoring, filtering, and analysis suite built in Python. Designed for cybersecurity professionals, network administrators, and security researchers.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)

---

## ✨ Features

### 🔍 Packet Capture
- **Raw Socket Capture**: High-performance packet capture using raw sockets
- **Multi-Interface Support**: Capture from any network interface
- **Promiscuous Mode**: Capture all packets on the network segment
- **Real-time Processing**: Low-latency packet processing pipeline

### 🚦 Advanced Filtering
- **Rule-Based Engine**: Priority-based rule matching system
- **IP Filtering**: Support for CIDR notation, wildcards, and exact matches
- **Port Filtering**: Filter by source/destination ports
- **Protocol Filtering**: TCP, UDP, ICMP, and custom protocols
- **Payload Inspection**: Regex-based payload matching
- **Size Filtering**: Filter by packet size ranges
- **Actions**: Allow, Block, Log, or Alert on match

### 🚨 Anomaly Detection
- **SYN Flood Detection**: Identifies potential DoS attacks
- **Port Scan Detection**: Detects horizontal and vertical port scans
- **Suspicious Port Monitoring**: Alerts on known malicious ports
- **Large Packet Detection**: Flags unusually large packets
- **Real-time Alerts**: Immediate notification of threats

### 📊 Traffic Analysis
- **Conversation Tracking**: Monitor bidirectional flows
- **Protocol Distribution**: Statistical breakdown by protocol
- **Hourly Distribution**: Traffic patterns over time
- **Top Talkers**: Identify busiest hosts and conversations
- **Bandwidth Metrics**: Packets/sec and Mbps calculations

### 📁 Export & Reporting
- **CSV Export**: Structured packet data for spreadsheet analysis
- **JSON Reports**: Machine-readable analysis reports
- **Comprehensive Reports**: Full session summaries with statistics
- **Custom Output Directory**: Organized file management

### 🖥️ Interactive Console
- **Live Packet Display**: Real-time packet visualization with colors
- **Command Interface**: Interactive commands during capture
- **Statistics Dashboard**: Periodic traffic statistics display
- **Session Reports**: Automatic final report generation

---

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- Root/Administrator privileges (for raw socket access)

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Optional Dependencies
```bash
pip install numpy pandas matplotlib flask
```

---

## 📖 Usage

### Basic Usage
```bash
# Run with default settings (requires root)
sudo python netguard.py

# Capture on specific interface
sudo python netguard.py -i eth0

# Load custom rules
sudo python netguard.py --rules rules.json

# Specify output directory
sudo python netguard.py --output-dir ./captures
```

### Command Line Options
```
usage: netguard.py [-h] [-i INTERFACE] [--no-color] [--rules RULES]
                   [--output-dir OUTPUT_DIR] [--promiscuous]

NetGuard - Advanced Network Monitoring Tool

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Network interface to capture
  --no-color            Disable colored output
  --rules RULES         JSON file with custom filter rules
  --output-dir OUTPUT_DIR
                        Output directory
  --promiscuous         Enable promiscuous mode (default: True)
```

### Interactive Commands
Once running, use these commands in the console:

| Command | Description |
|---------|-------------|
| `stats` | Show current traffic statistics |
| `filter <expr>` | Add a display filter (e.g., `filter tcp port 80`) |
| `rules` | Show active filtering rules |
| `export <format>` | Export data (`csv`, `json`, `report`) |
| `pause` | Pause packet display |
| `resume` | Resume packet display |
| `stop` / `exit` | Stop capture and exit |
| `help` | Show help message |

---

## 🔧 Configuration

### Custom Rules
Create a JSON file with your filtering rules:

```json
[
  {
    "name": "block_malware_port",
    "dst_port": 4444,
    "action": "block",
    "priority": 1
  },
  {
    "name": "alert_ssh",
    "dst_port": 22,
    "action": "alert",
    "priority": 10
  }
]
```

**Rule Parameters:**
- `name`: Unique rule identifier
- `src_ip` / `dst_ip`: IP address, CIDR (e.g., `192.168.1.0/24`), or wildcard (e.g., `192.168.*.*`)
- `src_port` / `dst_port`: Port number
- `protocol`: `TCP`, `UDP`, `ICMP`
- `min_size` / `max_size`: Packet size in bytes
- `payload_regex`: Regex pattern for payload inspection
- `action`: `allow`, `block`, `log`, or `alert`
- `priority`: Lower number = higher priority (1-1000)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    NetGuard Architecture                     │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │ Raw Socket   │───▶│ Packet       │───▶│ Filter       │  │
│  │ Capture      │    │ Parser       │    │ Engine       │  │
│  └──────────────┘    └──────────────┘    └──────┬───────┘  │
│                                                 │          │
│                    ┌────────────────────────────┘          │
│                    ▼                                       │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │ Anomaly      │◄───│ Traffic      │◄───│ Interactive  │  │
│  │ Detector     │    │ Analyzer     │    │ Console      │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                   │                   │           │
│         └───────────────────┼───────────────────┘           │
│                             ▼                              │
│                    ┌──────────────┐    ┌──────────────┐    │
│                    │ Output       │───▶│ Export       │    │
│                    │ Manager      │    │ (CSV/JSON)   │    │
│                    └──────────────┘    └──────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔒 Security Features

- **Malicious Port Blocking**: Pre-configured rules for known attack vectors
- **DoS Detection**: SYN flood and connection rate monitoring
- **Port Scan Detection**: Identifies reconnaissance activity
- **Payload Inspection**: Regex-based content filtering
- **Real-time Alerts**: Immediate threat notification

### Default Blocked Ports
| Port | Service | Threat |
|------|---------|--------|
| 4444 | Metasploit | Backdoor |
| 12345 | NetBus | Trojan |
| 31337 | BackOrifice | Trojan |
| 6667 | IRC | Botnet C&C |

---

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                    NETGUARD - Advanced Network Monitoring Tool              ║
╚══════════════════════════════════════════════════════════════════════════════╝

[+] Capture started on interface: eth0

Commands: stats | filter | rules | export | stop | help

netguard> 
14:32:15.123 | TCP   | 192.168.1.100:54321 -> 142.250.80.46:443    [HTTPS] [SA] |   66 bytes | TTL:64
14:32:15.124 | UDP   | 192.168.1.100:12345 -> 8.8.8.8:53          [DNS]  |   82 bytes | TTL:64
14:32:15.125 | TCP   | 192.168.1.100:54322 -> 142.250.80.46:443    [HTTPS] [A]  |   52 bytes | TTL:64
[ALERT] 14:32:15.200 | TCP   | 10.0.0.50:12345    -> 192.168.1.10:22      [SSH] [S]  |   66 bytes | TTL:128

📊 Stats: 1,234 pkts | 2.45 MB | 45.2 pps | 3.5 Mbps | Srcs: 15 | Dsts: 23
⚠️  Alerts: 3 total | HIGH: 1 | MEDIUM: 2
```

---

## 🛠️ Advanced Usage

### Programmatic API
```python
from netguard import PacketCapture, FilterEngine, FilterRule

# Create capture instance
capture = PacketCapture(interface="eth0")

# Add filter rules
engine = FilterEngine()
engine.add_rule(FilterRule("block_ssh", dst_port=22, action="block"))

# Add callback
def on_packet(packet):
    print(f"Captured: {packet.src_ip} -> {packet.dst_ip}")

capture.add_callback(on_packet)
capture.start()
```

### Custom Anomaly Detection
```python
from netguard import AnomalyDetector

detector = AnomalyDetector()
detector.thresholds['syn_flood'] = 50  # Custom threshold
detector.thresholds['port_scan'] = 10
```

---

## 📝 License

This project is licensed under the MIT License.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

---

## ⚠️ Disclaimer

This tool is intended for authorized network monitoring and security testing only. 
Always ensure you have proper authorization before capturing network traffic.

---

**Made with ❤️ for the cybersecurity community**
