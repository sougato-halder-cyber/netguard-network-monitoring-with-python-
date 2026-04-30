#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    NETGUARD - Advanced Network Monitoring Tool              ║
║                         Packet Capture & Analysis Suite                      ║
╚══════════════════════════════════════════════════════════════════════════════╝

Author: Network Security Team
Version: 2.0.0
License: MIT
Description: A high-end network monitoring, filtering, and analysis tool
             designed for cybersecurity professionals and network administrators.
"""

import socket
import struct
import threading
import time
import json
import csv
import argparse
import signal
import sys
import os
import hashlib
import ipaddress
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional, Callable, Set
from dataclasses import dataclass, asdict
from enum import Enum
import queue
import re

# Optional imports with graceful degradation
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS & CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

class Protocol(Enum):
    TCP = 6
    UDP = 17
    ICMP = 1
    IGMP = 2
    ARP = 0x0806
    UNKNOWN = 0

PROTOCOL_NAMES = {
    1: "ICMP",
    2: "IGMP", 
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}

WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP",
    135: "MSRPC", 137: "NETBIOS", 138: "NETBIOS", 139: "NETBIOS",
    143: "IMAP", 161: "SNMP", 162: "SNMP-TRAP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "SYSLOG",
    587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "ORACLE", 3306: "MYSQL", 3389: "RDP",
    5432: "POSTGRESQL", 5900: "VNC", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    9200: "ELASTICSEARCH", 27017: "MONGODB",
}

SUSPICIOUS_PORTS = {
    4444: "METASPLOIT", 5555: "ADB", 6666: "IRC-ALT", 6667: "IRC",
    31337: "BACKORIFICE", 12345: "NETBUS", 27374: "SUBSEVEN",
}

BANNER = f"""
{Fore.CYAN if COLORAMA_AVAILABLE else ''}
   ███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
   ████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
   ██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
   ██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
   ██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
   ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}
   Advanced Network Monitoring, Filtering & Analysis Suite v2.0.0
   ─────────────────────────────────────────────────────────────
"""


# ═══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class PacketInfo:
    """Represents captured packet information."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length: int
    flags: Optional[str]
    payload_size: int
    ttl: Optional[int]
    checksum: Optional[str]
    raw_data: bytes
    interface: str = "unknown"

    @property
    def hash(self) -> str:
        """Generate unique hash for deduplication."""
        data = f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.protocol}-{self.length}"
        return hashlib.md5(data.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict:
        return {
            "timestamp": datetime.fromtimestamp(self.timestamp).isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "length": self.length,
            "flags": self.flags,
            "payload_size": self.payload_size,
            "ttl": self.ttl,
            "checksum": self.checksum,
            "interface": self.interface,
        }


@dataclass  
class TrafficStats:
    """Aggregated traffic statistics."""
    total_packets: int = 0
    total_bytes: int = 0
    unique_sources: Set = None
    unique_destinations: Set = None
    protocol_counts: Counter = None
    port_counts: Counter = None
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    start_time: float = 0.0

    def __post_init__(self):
        if self.unique_sources is None:
            self.unique_sources = set()
        if self.unique_destinations is None:
            self.unique_destinations = set()
        if self.protocol_counts is None:
            self.protocol_counts = Counter()
        if self.port_counts is None:
            self.port_counts = Counter()

    def update(self, packet: PacketInfo):
        self.total_packets += 1
        self.total_bytes += packet.length
        self.unique_sources.add(packet.src_ip)
        self.unique_destinations.add(packet.dst_ip)
        self.protocol_counts[packet.protocol] += 1
        if packet.dst_port:
            self.port_counts[packet.dst_port] += 1

    @property
    def duration(self) -> float:
        return time.time() - self.start_time if self.start_time else 0

    @property
    def summary(self) -> Dict:
        duration = max(self.duration, 1)
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "total_mb": round(self.total_bytes / (1024 * 1024), 2),
            "unique_sources": len(self.unique_sources),
            "unique_destinations": len(self.unique_destinations),
            "protocols": dict(self.protocol_counts),
            "top_ports": dict(self.port_counts.most_common(10)),
            "packets_per_second": round(self.total_packets / duration, 2),
            "mbps": round((self.total_bytes * 8) / (duration * 1024 * 1024), 2),
            "duration_seconds": round(duration, 2),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# FILTER ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class FilterRule:
    """Represents a packet filtering rule."""

    def __init__(self, 
                 name: str,
                 src_ip: Optional[str] = None,
                 dst_ip: Optional[str] = None,
                 src_port: Optional[int] = None,
                 dst_port: Optional[int] = None,
                 protocol: Optional[str] = None,
                 min_size: Optional[int] = None,
                 max_size: Optional[int] = None,
                 payload_regex: Optional[str] = None,
                 action: str = "allow",  # allow, block, log, alert
                 priority: int = 100):
        self.name = name
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol.upper() if protocol else None
        self.min_size = min_size
        self.max_size = max_size
        self.payload_regex = re.compile(payload_regex) if payload_regex else None
        self.action = action
        self.priority = priority
        self.match_count = 0

    def matches(self, packet: PacketInfo) -> bool:
        """Check if packet matches this filter rule."""
        if self.src_ip and not self._ip_matches(packet.src_ip, self.src_ip):
            return False
        if self.dst_ip and not self._ip_matches(packet.dst_ip, self.dst_ip):
            return False
        if self.src_port and packet.src_port != self.src_port:
            return False
        if self.dst_port and packet.dst_port != self.dst_port:
            return False
        if self.protocol and packet.protocol != self.protocol:
            return False
        if self.min_size and packet.length < self.min_size:
            return False
        if self.max_size and packet.length > self.max_size:
            return False
        if self.payload_regex:
            try:
                if not self.payload_regex.search(packet.raw_data.decode('utf-8', errors='ignore')):
                    return False
            except:
                return False

        self.match_count += 1
        return True

    def _ip_matches(self, ip: str, pattern: str) -> bool:
        """Check if IP matches pattern (supports CIDR and wildcards)."""
        if '/' in pattern:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(pattern, strict=False)
        if '*' in pattern:
            regex = pattern.replace('.', '\.').replace('*', '.*')
            return re.match(f"^{regex}$", ip) is not None
        return ip == pattern

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "min_size": self.min_size,
            "max_size": self.max_size,
            "payload_regex": self.payload_regex.pattern if self.payload_regex else None,
            "action": self.action,
            "priority": self.priority,
            "match_count": self.match_count,
        }


class FilterEngine:
    """Advanced packet filtering engine with rule management."""

    def __init__(self):
        self.rules: List[FilterRule] = []
        self.blocked_packets = 0
        self.alerted_packets = 0
        self.logged_packets = 0

    def add_rule(self, rule: FilterRule):
        """Add a filtering rule."""
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)

    def remove_rule(self, name: str):
        """Remove a rule by name."""
        self.rules = [r for r in self.rules if r.name != name]

    def evaluate(self, packet: PacketInfo) -> Tuple[bool, Optional[str]]:
        """
        Evaluate packet against all rules.
        Returns: (should_forward, action_name)
        """
        for rule in self.rules:
            if rule.matches(packet):
                if rule.action == "block":
                    self.blocked_packets += 1
                    return False, rule.name
                elif rule.action == "alert":
                    self.alerted_packets += 1
                    return True, f"ALERT:{rule.name}"
                elif rule.action == "log":
                    self.logged_packets += 1
                    return True, f"LOG:{rule.name}"
                elif rule.action == "allow":
                    return True, rule.name
        return True, None

    def load_rules_from_file(self, filepath: str):
        """Load rules from JSON file."""
        with open(filepath, 'r') as f:
            rules_data = json.load(f)
        for rule_data in rules_data:
            self.add_rule(FilterRule(**rule_data))

    def save_rules_to_file(self, filepath: str):
        """Save rules to JSON file."""
        with open(filepath, 'w') as f:
            json.dump([r.to_dict() for r in self.rules], f, indent=2)


# ═══════════════════════════════════════════════════════════════════════════════
# PACKET CAPTURE ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class PacketCapture:
    """Multi-interface packet capture engine."""

    def __init__(self, interface: Optional[str] = None, 
                 promiscuous: bool = True,
                 buffer_size: int = 65536):
        self.interface = interface
        self.promiscuous = promiscuous
        self.buffer_size = buffer_size
        self.running = False
        self.packet_queue = queue.Queue(maxsize=10000)
        self.stats = TrafficStats()
        self.stats.start_time = time.time()
        self.callbacks: List[Callable] = []
        self._socket = None
        self._thread = None

    def _create_socket(self) -> socket.socket:
        """Create raw socket for packet capture."""
        try:
            # Linux
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 
                                socket.ntohs(3))  # ETH_P_ALL
            if self.interface:
                sock.bind((self.interface, 0))
            return sock
        except (AttributeError, OSError):
            # Windows / macOS fallback
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                    socket.IPPROTO_IP)
                sock.bind((self._get_default_ip(), 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                if os.name == 'nt':  # Windows
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                return sock
            except Exception as e:
                raise RuntimeError(f"Cannot create raw socket: {e}. "
                                 "Run with administrator/root privileges.")

    def _get_default_ip(self) -> str:
        """Get default interface IP."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def _parse_ethernet(self, data: bytes) -> Tuple[str, int, bytes]:
        """Parse Ethernet header."""
        if len(data) < 14:
            return "unknown", 0x0800, data
        eth_header = struct.unpack('!6s6sH', data[:14])
        eth_type = socket.ntohs(eth_header[2])
        return "ethernet", eth_type, data[14:]

    def _parse_ip(self, data: bytes) -> Optional[Dict]:
        """Parse IP header."""
        if len(data) < 20:
            return None

        version_ihl = data[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0xF) * 4

        if version != 4 or len(data) < ihl:
            return None

        ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])

        return {
            'version': version,
            'ihl': ihl,
            'ttl': ip_header[5],
            'protocol': ip_header[6],
            'src_ip': socket.inet_ntoa(ip_header[8]),
            'dst_ip': socket.inet_ntoa(ip_header[9]),
            'total_length': ip_header[2],
            'header_checksum': ip_header[7],
            'payload': data[ihl:],
        }

    def _parse_tcp(self, data: bytes) -> Optional[Dict]:
        """Parse TCP header."""
        if len(data) < 20:
            return None
        tcp_header = struct.unpack('!HHLLBBHHH', data[:20])

        flags = tcp_header[5]
        flag_str = ""
        if flags & 0x02: flag_str += "S"
        if flags & 0x10: flag_str += "A"
        if flags & 0x01: flag_str += "F"
        if flags & 0x04: flag_str += "R"
        if flags & 0x08: flag_str += "P"
        if flags & 0x20: flag_str += "U"

        data_offset = (tcp_header[4] >> 4) * 4

        return {
            'src_port': tcp_header[0],
            'dst_port': tcp_header[1],
            'seq': tcp_header[2],
            'ack': tcp_header[3],
            'flags': flag_str if flag_str else "-",
            'window': tcp_header[6],
            'checksum': tcp_header[7],
            'payload': data[data_offset:],
        }

    def _parse_udp(self, data: bytes) -> Optional[Dict]:
        """Parse UDP header."""
        if len(data) < 8:
            return None
        udp_header = struct.unpack('!HHHH', data[:8])
        return {
            'src_port': udp_header[0],
            'dst_port': udp_header[1],
            'length': udp_header[2],
            'checksum': udp_header[3],
            'payload': data[8:],
        }

    def _parse_icmp(self, data: bytes) -> Optional[Dict]:
        """Parse ICMP header."""
        if len(data) < 4:
            return None
        icmp_header = struct.unpack('!BBH', data[:4])
        return {
            'type': icmp_header[0],
            'code': icmp_header[1],
            'checksum': icmp_header[2],
            'payload': data[4:],
        }

    def _process_packet(self, raw_data: bytes, interface: str = "unknown"):
        """Process raw packet data."""
        try:
            _, eth_type, ip_data = self._parse_ethernet(raw_data)

            if eth_type != 0x0800:  # Not IPv4
                return

            ip_info = self._parse_ip(ip_data)
            if not ip_info:
                return

            protocol = ip_info['protocol']
            src_port = dst_port = None
            flags = None
            payload = ip_info['payload']

            if protocol == Protocol.TCP.value:
                tcp_info = self._parse_tcp(payload)
                if tcp_info:
                    src_port = tcp_info['src_port']
                    dst_port = tcp_info['dst_port']
                    flags = tcp_info['flags']
                    payload = tcp_info['payload']
            elif protocol == Protocol.UDP.value:
                udp_info = self._parse_udp(payload)
                if udp_info:
                    src_port = udp_info['src_port']
                    dst_port = udp_info['dst_port']
                    payload = udp_info['payload']
            elif protocol == Protocol.ICMP.value:
                icmp_info = self._parse_icmp(payload)
                if icmp_info:
                    payload = icmp_info['payload']

            proto_name = PROTOCOL_NAMES.get(protocol, f"PROTO-{protocol}")

            packet = PacketInfo(
                timestamp=time.time(),
                src_ip=ip_info['src_ip'],
                dst_ip=ip_info['dst_ip'],
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto_name,
                length=len(raw_data),
                flags=flags,
                payload_size=len(payload),
                ttl=ip_info['ttl'],
                checksum=hex(ip_info['header_checksum']),
                raw_data=raw_data,
                interface=interface,
            )

            self.stats.update(packet)

            # Execute callbacks
            for callback in self.callbacks:
                try:
                    callback(packet)
                except Exception as e:
                    print(f"Callback error: {e}")

            # Add to queue (non-blocking)
            try:
                self.packet_queue.put_nowait(packet)
            except queue.Full:
                pass

        except Exception as e:
            pass  # Silently drop malformed packets

    def _capture_loop(self):
        """Main capture loop."""
        self._socket = self._create_socket()
        self._socket.settimeout(1.0)

        while self.running:
            try:
                raw_data, addr = self._socket.recvfrom(self.buffer_size)
                self._process_packet(raw_data, self.interface or "default")
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"Capture error: {e}")
                break

    def start(self):
        """Start packet capture."""
        if self.running:
            return
        self.running = True
        self.stats.start_time = time.time()
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        print(f"{Fore.GREEN if COLORAMA_AVAILABLE else ''}[+] Capture started on interface: {self.interface or 'default'}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")

    def stop(self):
        """Stop packet capture."""
        self.running = False
        if self._socket:
            try:
                self._socket.close()
            except:
                pass
        if self._thread:
            self._thread.join(timeout=2)
        print(f"{Fore.YELLOW if COLORAMA_AVAILABLE else ''}[-] Capture stopped{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")

    def add_callback(self, callback: Callable):
        """Add packet processing callback."""
        self.callbacks.append(callback)

    def get_packets(self, count: int = 100) -> List[PacketInfo]:
        """Get packets from queue."""
        packets = []
        for _ in range(count):
            try:
                packets.append(self.packet_queue.get_nowait())
            except queue.Empty:
                break
        return packets


# ═══════════════════════════════════════════════════════════════════════════════
# ANALYSIS MODULES
# ═══════════════════════════════════════════════════════════════════════════════

class AnomalyDetector:
    """Detect network anomalies and potential threats."""

    def __init__(self):
        self.connection_tracker: Dict[str, Dict] = defaultdict(lambda: {
            'count': 0, 'first_seen': time.time(), 'ports': set(), 'bytes': 0
        })
        self.syn_flood_tracker: Dict[str, int] = defaultdict(int)
        self.port_scan_tracker: Dict[str, Set] = defaultdict(set)
        self.alerts: List[Dict] = []
        self.thresholds = {
            'syn_flood': 100,      # SYN packets per second
            'port_scan': 20,       # Unique ports per source
            'connection_rate': 50, # Connections per second
            'large_packet': 65000, # Suspiciously large packets
        }

    def analyze(self, packet: PacketInfo) -> List[Dict]:
        """Analyze packet for anomalies."""
        alerts = []
        src_key = packet.src_ip

        # SYN Flood Detection
        if packet.flags and 'S' in packet.flags and 'A' not in packet.flags:
            self.syn_flood_tracker[src_key] += 1
            if self.syn_flood_tracker[src_key] > self.thresholds['syn_flood']:
                alerts.append({
                    'type': 'SYN_FLOOD',
                    'severity': 'HIGH',
                    'source': src_key,
                    'details': f"{self.syn_flood_tracker[src_key]} SYN packets detected",
                    'timestamp': packet.timestamp,
                })

        # Port Scan Detection
        if packet.dst_port:
            self.port_scan_tracker[src_key].add(packet.dst_port)
            if len(self.port_scan_tracker[src_key]) > self.thresholds['port_scan']:
                alerts.append({
                    'type': 'PORT_SCAN',
                    'severity': 'MEDIUM',
                    'source': src_key,
                    'details': f"Scanning {len(self.port_scan_tracker[src_key])} ports",
                    'timestamp': packet.timestamp,
                })

        # Large Packet Detection
        if packet.length > self.thresholds['large_packet']:
            alerts.append({
                'type': 'LARGE_PACKET',
                'severity': 'LOW',
                'source': src_key,
                'details': f"Packet size: {packet.length} bytes",
                'timestamp': packet.timestamp,
            })

        # Suspicious Port Detection
        if packet.dst_port in SUSPICIOUS_PORTS:
            alerts.append({
                'type': 'SUSPICIOUS_PORT',
                'severity': 'HIGH',
                'source': src_key,
                'details': f"Connection to {SUSPICIOUS_PORTS[packet.dst_port]} port {packet.dst_port}",
                'timestamp': packet.timestamp,
            })

        self.alerts.extend(alerts)
        return alerts

    def get_summary(self) -> Dict:
        """Get anomaly summary."""
        severity_counts = Counter(a['severity'] for a in self.alerts)
        type_counts = Counter(a['type'] for a in self.alerts)
        return {
            'total_alerts': len(self.alerts),
            'severity_distribution': dict(severity_counts),
            'alert_types': dict(type_counts),
            'recent_alerts': self.alerts[-10:],
        }


class TrafficAnalyzer:
    """Advanced traffic analysis and reporting."""

    def __init__(self):
        self.conversations: Dict[str, Dict] = defaultdict(lambda: {
            'packets': 0, 'bytes': 0, 'start': float('inf'), 'end': 0
        })
        self.hourly_stats: Dict[int, Counter] = defaultdict(Counter)

    def analyze(self, packet: PacketInfo):
        """Analyze packet for traffic patterns."""
        conv_key = tuple(sorted([f"{packet.src_ip}:{packet.src_port}", 
                                  f"{packet.dst_ip}:{packet.dst_port}"]))

        self.conversations[conv_key]['packets'] += 1
        self.conversations[conv_key]['bytes'] += packet.length
        self.conversations[conv_key]['start'] = min(
            self.conversations[conv_key]['start'], packet.timestamp)
        self.conversations[conv_key]['end'] = max(
            self.conversations[conv_key]['end'], packet.timestamp)

        hour = datetime.fromtimestamp(packet.timestamp).hour
        self.hourly_stats[hour][packet.protocol] += 1

    def get_top_conversations(self, n: int = 10) -> List[Dict]:
        """Get top conversations by bytes."""
        sorted_convs = sorted(
            self.conversations.items(), 
            key=lambda x: x[1]['bytes'], 
            reverse=True
        )[:n]

        return [
            {
                'conversation': f"{conv[0][0]} <-> {conv[0][1]}",
                'packets': conv[1]['packets'],
                'bytes': conv[1]['bytes'],
                'duration': round(conv[1]['end'] - conv[1]['start'], 2),
            }
            for conv in sorted_convs
        ]

    def get_hourly_distribution(self) -> Dict:
        """Get traffic distribution by hour."""
        return {
            f"{hour:02d}:00": dict(stats)
            for hour, stats in sorted(self.hourly_stats.items())
        }


# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUT & REPORTING
# ═══════════════════════════════════════════════════════════════════════════════

class OutputManager:
    """Manage output formatting and file exports."""

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    def format_packet(self, packet: PacketInfo, color: bool = True) -> str:
        """Format packet for display."""
        proto_color = {
            "TCP": Fore.GREEN if COLORAMA_AVAILABLE else "",
            "UDP": Fore.YELLOW if COLORAMA_AVAILABLE else "",
            "ICMP": Fore.RED if COLORAMA_AVAILABLE else "",
        }.get(packet.protocol, Fore.WHITE if COLORAMA_AVAILABLE else "")

        src_port_str = f":{packet.src_port}" if packet.src_port else ""
        dst_port_str = f":{packet.dst_port}" if packet.dst_port else ""

        port_service = ""
        if packet.dst_port:
            service = WELL_KNOWN_PORTS.get(packet.dst_port) or SUSPICIOUS_PORTS.get(packet.dst_port)
            if service:
                port_service = f" [{service}]"

        flags_str = f" [{packet.flags}]" if packet.flags else ""

        timestamp = datetime.fromtimestamp(packet.timestamp).strftime("%H:%M:%S.%f")[:-3]

        reset = Style.RESET_ALL if COLORAMA_AVAILABLE else ""

        return (
            f"{timestamp} | "
            f"{proto_color}{packet.protocol:5}{reset} | "
            f"{packet.src_ip:15}{src_port_str:6} -> "
            f"{packet.dst_ip:15}{dst_port_str:6}"
            f"{port_service}"
            f"{flags_str} | "
            f"{packet.length:5} bytes | "
            f"TTL:{packet.ttl or '-':3}"
        )

    def export_to_csv(self, packets: List[PacketInfo], filename: Optional[str] = None):
        """Export packets to CSV."""
        if not filename:
            filename = f"capture_{self.session_id}.csv"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, 'w', newline='') as f:
            if packets:
                writer = csv.DictWriter(f, fieldnames=packets[0].to_dict().keys())
                writer.writeheader()
                for packet in packets:
                    writer.writerow(packet.to_dict())

        print(f"{Fore.CYAN if COLORAMA_AVAILABLE else ''}[+] Exported {len(packets)} packets to {filepath}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        return filepath

    def export_to_json(self, data: Dict, filename: Optional[str] = None):
        """Export data to JSON."""
        if not filename:
            filename = f"report_{self.session_id}.json"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        print(f"{Fore.CYAN if COLORAMA_AVAILABLE else ''}[+] Exported report to {filepath}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        return filepath

    def generate_report(self, stats: TrafficStats, 
                       anomaly_detector: AnomalyDetector,
                       traffic_analyzer: TrafficAnalyzer) -> Dict:
        """Generate comprehensive analysis report."""
        report = {
            "session_id": self.session_id,
            "generated_at": datetime.now().isoformat(),
            "traffic_summary": stats.summary,
            "anomaly_detection": anomaly_detector.get_summary(),
            "top_conversations": traffic_analyzer.get_top_conversations(),
            "hourly_distribution": traffic_analyzer.get_hourly_distribution(),
        }
        return report


# ═══════════════════════════════════════════════════════════════════════════════
# INTERACTIVE CONSOLE
# ═══════════════════════════════════════════════════════════════════════════════

class InteractiveConsole:
    """Interactive command-line interface."""

    def __init__(self, capture: PacketCapture, filter_engine: FilterEngine,
                 anomaly_detector: AnomalyDetector, traffic_analyzer: TrafficAnalyzer,
                 output_manager: OutputManager):
        self.capture = capture
        self.filter_engine = filter_engine
        self.anomaly_detector = anomaly_detector
        self.traffic_analyzer = traffic_analyzer
        self.output_manager = output_manager
        self.display_packets = True
        self.display_stats_interval = 10
        self.last_stats_time = time.time()

    def _print_header(self):
        """Print display header."""
        print("\n" + "=" * 100)
        print(f"{'TIME':12} | {'PROTO':5} | {'SOURCE':22} -> {'DESTINATION':22} | {'INFO':20}")
        print("-" * 100)

    def _show_stats(self):
        """Display current statistics."""
        stats = self.capture.stats.summary
        print(f"\n{Fore.CYAN if COLORAMA_AVAILABLE else ''}"
              f"📊 Stats: {stats['total_packets']} pkts | "
              f"{stats['total_mb']} MB | "
              f"{stats['packets_per_second']} pps | "
              f"{stats['mbps']} Mbps | "
              f"Srcs: {stats['unique_sources']} | Dsts: {stats['unique_destinations']}"
              f"{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")

        # Show recent alerts
        alerts = self.anomaly_detector.get_summary()
        if alerts['total_alerts'] > 0:
            print(f"{Fore.RED if COLORAMA_AVAILABLE else ''}"
                  f"⚠️  Alerts: {alerts['total_alerts']} total | "
                  f"HIGH: {alerts['severity_distribution'].get('HIGH', 0)} | "
                  f"MEDIUM: {alerts['severity_distribution'].get('MEDIUM', 0)}"
                  f"{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")

    def _packet_callback(self, packet: PacketInfo):
        """Process captured packet."""
        # Apply filters
        should_forward, action = self.filter_engine.evaluate(packet)

        if not should_forward:
            return

        # Analyze
        self.anomaly_detector.analyze(packet)
        self.traffic_analyzer.analyze(packet)

        # Display
        if self.display_packets:
            formatted = self.output_manager.format_packet(packet)
            if action and "ALERT" in action:
                print(f"{Fore.RED if COLORAMA_AVAILABLE else ''}[ALERT] {formatted}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            elif action and "LOG" in action:
                print(f"{Fore.MAGENTA if COLORAMA_AVAILABLE else ''}[LOG] {formatted}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            else:
                print(formatted)

        # Periodic stats
        if time.time() - self.last_stats_time > self.display_stats_interval:
            self._show_stats()
            self.last_stats_time = time.time()

    def run(self):
        """Run interactive console."""
        self.capture.add_callback(self._packet_callback)
        self.capture.start()

        print("\n" + BANNER)
        print(f"{Fore.GREEN if COLORAMA_AVAILABLE else ''}Commands: stats | filter | rules | export | stop | help{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}\n")

        try:
            while self.capture.running:
                try:
                    cmd = input(f"{Fore.CYAN if COLORAMA_AVAILABLE else ''}netguard> {Style.RESET_ALL if COLORAMA_AVAILABLE else ''}").strip().lower()

                    if cmd == "stop" or cmd == "exit" or cmd == "quit":
                        break
                    elif cmd == "stats":
                        self._show_stats()
                    elif cmd == "help":
                        self._show_help()
                    elif cmd.startswith("filter "):
                        self._handle_filter(cmd[7:])
                    elif cmd == "rules":
                        self._show_rules()
                    elif cmd.startswith("export "):
                        self._handle_export(cmd[7:])
                    elif cmd == "pause":
                        self.display_packets = False
                        print("Packet display paused. Type 'resume' to continue.")
                    elif cmd == "resume":
                        self.display_packets = True
                        print("Packet display resumed.")
                    elif cmd:
                        print(f"Unknown command: {cmd}")

                except EOFError:
                    break
                except KeyboardInterrupt:
                    break
        finally:
            self.capture.stop()
            self._generate_final_report()

    def _show_help(self):
        """Show help message."""
        help_text = """
Available Commands:
  stats              - Show current traffic statistics
  filter <expr>      - Add a display filter (e.g., 'filter tcp port 80')
  rules              - Show active filtering rules
  export <format>    - Export data (csv, json, report)
  pause              - Pause packet display
  resume             - Resume packet display
  stop / exit        - Stop capture and exit
  help               - Show this help message
        """
        print(help_text)

    def _handle_filter(self, expr: str):
        """Handle filter command."""
        print(f"Adding filter: {expr}")
        # Simplified filter parsing
        parts = expr.split()
        kwargs = {}
        for i, part in enumerate(parts):
            if part == "tcp":
                kwargs['protocol'] = "TCP"
            elif part == "udp":
                kwargs['protocol'] = "UDP"
            elif part == "port" and i + 1 < len(parts):
                kwargs['dst_port'] = int(parts[i + 1])
            elif part == "host" and i + 1 < len(parts):
                kwargs['src_ip'] = parts[i + 1]

        rule = FilterRule(name=f"user_filter_{len(self.filter_engine.rules)}", 
                         action="allow", priority=10, **kwargs)
        self.filter_engine.add_rule(rule)
        print(f"Filter added: {rule.to_dict()}")

    def _show_rules(self):
        """Show active rules."""
        print(f"\n{'NAME':20} | {'PROTO':6} | {'PORT':6} | {'ACTION':8} | {'MATCHES':8}")
        print("-" * 70)
        for rule in self.filter_engine.rules:
            print(f"{rule.name:20} | {rule.protocol or 'ANY':6} | "
                  f"{str(rule.dst_port) if rule.dst_port else 'ANY':6} | "
                  f"{rule.action:8} | {rule.match_count:8}")

    def _handle_export(self, fmt: str):
        """Handle export command."""
        packets = []
        while True:
            try:
                packets.append(self.capture.packet_queue.get_nowait())
            except queue.Empty:
                break

        if fmt == "csv":
            self.output_manager.export_to_csv(packets)
        elif fmt == "json":
            report = self.output_manager.generate_report(
                self.capture.stats, self.anomaly_detector, self.traffic_analyzer
            )
            self.output_manager.export_to_json(report)
        elif fmt == "report":
            report = self.output_manager.generate_report(
                self.capture.stats, self.anomaly_detector, self.traffic_analyzer
            )
            self.output_manager.export_to_json(report, f"full_report_{self.output_manager.session_id}.json")
        else:
            print(f"Unknown format: {fmt}. Use: csv, json, report")

    def _generate_final_report(self):
        """Generate final session report."""
        print("\n" + "=" * 60)
        print("FINAL SESSION REPORT")
        print("=" * 60)

        report = self.output_manager.generate_report(
            self.capture.stats, self.anomaly_detector, self.traffic_analyzer
        )

        print(f"\nSession ID: {report['session_id']}")
        print(f"Duration: {report['traffic_summary']['duration_seconds']} seconds")
        print(f"Total Packets: {report['traffic_summary']['total_packets']}")
        print(f"Total Data: {report['traffic_summary']['total_mb']} MB")
        print(f"Unique Sources: {report['traffic_summary']['unique_sources']}")
        print(f"Unique Destinations: {report['traffic_summary']['unique_destinations']}")

        print(f"\nProtocol Distribution:")
        for proto, count in report['traffic_summary']['protocols'].items():
            print(f"  {proto}: {count}")

        print(f"\nTop Conversations:")
        for conv in report['top_conversations'][:5]:
            print(f"  {conv['conversation']}: {conv['packets']} pkts, {conv['bytes']} bytes")

        print(f"\nAnomaly Alerts: {report['anomaly_detection']['total_alerts']}")

        # Save final report
        self.output_manager.export_to_json(report, f"final_report_{self.output_manager.session_id}.json")
        print("\n" + "=" * 60)


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def create_default_rules() -> List[FilterRule]:
    """Create default security rules."""
    return [
        FilterRule("block_malware_port_4444", dst_port=4444, action="block", priority=1),
        FilterRule("block_netbus", dst_port=12345, action="block", priority=1),
        FilterRule("alert_ssh", dst_port=22, action="log", priority=50),
        FilterRule("alert_http", dst_port=80, action="log", priority=100),
        FilterRule("alert_https", dst_port=443, action="log", priority=100),
    ]

def main():
    parser = argparse.ArgumentParser(
        description="NetGuard - Advanced Network Monitoring Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python netguard.py                    # Start with default settings
  sudo python netguard.py -i eth0            # Capture on specific interface
  sudo python netguard.py --no-color       # Disable colored output
  sudo python netguard.py --rules rules.json # Load custom rules
        """
    )

    parser.add_argument("-i", "--interface", help="Network interface to capture")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--rules", help="JSON file with custom filter rules")
    parser.add_argument("--output-dir", default="./output", help="Output directory")
    parser.add_argument("--promiscuous", action="store_true", default=True, 
                       help="Enable promiscuous mode")

    args = parser.parse_args()

    # Check privileges
    if os.name != 'nt' and os.geteuid() != 0:
        print(f"{Fore.RED if COLORAMA_AVAILABLE else ''}⚠️  Warning: Root privileges required for packet capture.{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        print("Run with: sudo python netguard.py")
        # Continue anyway for testing

    # Initialize components
    capture = PacketCapture(
        interface=args.interface,
        promiscuous=args.promiscuous
    )

    filter_engine = FilterEngine()

    # Add default rules
    for rule in create_default_rules():
        filter_engine.add_rule(rule)

    # Load custom rules if provided
    if args.rules and os.path.exists(args.rules):
        filter_engine.load_rules_from_file(args.rules)
        print(f"Loaded custom rules from {args.rules}")

    anomaly_detector = AnomalyDetector()
    traffic_analyzer = TrafficAnalyzer()
    output_manager = OutputManager(output_dir=args.output_dir)

    # Run interactive console
    console = InteractiveConsole(
        capture, filter_engine, anomaly_detector, 
        traffic_analyzer, output_manager
    )
    console.run()


if __name__ == "__main__":
    main()
