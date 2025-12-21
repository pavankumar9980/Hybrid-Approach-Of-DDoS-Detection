# Hybrid Approach of DDoS Detection System

**Real-Time DDoS Intrusion Detection with Attacker IP Tracking**

**Project by Pavan Kumar (pavankumar9980)**  
B.Tech Final Year Project - 2025

## Project Overview

This is a real-time Hybrid DDoS Detection System built using Python. It captures live network packets, detects various DDoS attacks, identifies the attack type, and shows the exact attacker IP on a web dashboard.

The system combines **rule-based detection** for known attacks and **machine learning** (Random Forest + Isolation Forest) for unknown/anomalous traffic.

Tested with real attacks from Kali Linux in VirtualBox bridged mode.

## Key Features

- **Live Packet Sniffing** using Scapy (real packets, not simulated)
- **Hybrid Detection**:
  - Rule-based for SYN Flood, UDP Flood, ICMP Flood, ACK Flood, HTTP/Volume Flood, Slowloris
  - ML-based for unknown attacks (Isolation Forest anomaly detection)
- **Attacker IP Tracking** (reverse engineering of IP header — shows source IP of attacker)
- **Real-Time Dashboard**:
  - Live graph (Packets/s and SYN/s)
  - Current attack type (big red/green text)
  - Live captured packet list (timestamp, source, dest, protocol, size, flags)
  - Click packet for details
  - Download captured packets as CSV/TXT
- **Works on any network** (home Wi-Fi, college, mobile hotspot — auto IP detection)
- **No false positives on normal browsing** (tuned thresholds)

## Technologies Used

- **Backend**: Python + Flask (API)
- **Packet Capture**: Scapy
- **Machine Learning**: Scikit-learn (Random Forest + Isolation Forest) trained on CIC-DDoS2019 dataset
- **Frontend**: HTML + CSS + JavaScript + Chart.js
- **Authentication**: JWT token
- **Deployment Ready**: Runs on laptop, can be deployed on cloud

## How to Run

1. Activate virtual environment:
   ```bash
   source venv/bin/activate
2. Run Flask backend:
   ```bash
   python3 app.py --host 0.0.0.0
3. In another terminal, run dashboard:
   ```bash
   source venv/bin/activate
   python3 -m http.server 8080
4. Open browser → http://127.0.0.1:8080 
   *The dashboard auto-connects to your current IP.

## Demo Attacks (From Kali Linux)

   **Replace YOUR_UBUNTU_IP with your Ubuntu IP (e.g., 10.13.247.244)**

   ```bash
   sudo hping3 -S --flood -p 80 YOUR_UBUNTU_IP        # SYN Flood
   sudo hping3 --udp --flood -p 53 YOUR_UBUNTU_IP     # UDP Flood
   sudo hping3 --icmp --flood YOUR_UBUNTU_IP          # ICMP Flood
   sudo hping3 -A --flood -p 80 YOUR_UBUNTU_IP        # ACK Flood
   sudo slowhttptest -c 1000 -H -i 10 -r 200 -t GET -u http://YOUR_UBUNTU_IP:8000   # Slowloris
   ```
## Future Scope

**Auto-block attacker IP using iptables**
**Geo-location of attacker**
**Cloud deployment (AWS/Google Cloud Run)**
**Mobile app alerts**
**Integration with firewalls**

