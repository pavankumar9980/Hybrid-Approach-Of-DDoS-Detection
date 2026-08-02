# Hybrid Approach of DDoS Detection
## System Architecture

## Overview

The Hybrid DDoS Detection System combines rule-based detection with Machine Learning techniques to identify malicious network traffic in real time.

The application continuously captures packets from the network interface, extracts traffic features, and classifies traffic as either normal or malicious.

---

# Architecture
Internet Traffic
↓

Packet Capture (Scapy)

↓

Feature Extraction

↓

Rule-Based Detection

↓

Machine Learning Detection
↓

Decision Engine

↓

Dashboard / Alert System

↓

CSV Log Storage

---

## Components

### Packet Capture

- Captures live packets using Scapy.
- Extracts packet headers.
- Stores packets temporarily for analysis.

### Feature Extraction

The following traffic features are extracted:

- Source IP
- Destination IP
- Source Port
- Destination Port
- Protocol
- Packet Length
- SYN Count
- Packet Rate
- Flow Duration
- Bytes Per Second

---

### Rule-Based Detection

Fast detection of common attacks.

Rules include:

- SYN Flood Detection
- UDP Flood Detection
- ICMP Flood Detection
- Packet Rate Threshold
- Connection Threshold

Advantages

- Very fast
- Low CPU usage
- Detects known attacks

---

### Machine Learning Detection

The extracted features are passed to the trained ML model.

Possible outputs

- Normal
- DoS Attack
- DDoS Attack

Advantages

- Detects unknown traffic patterns
- Higher accuracy
- Reduces false positives

---

### Decision Engine

Combines

- Rule-based score
- Machine Learning prediction

Final Result

- Normal Traffic
- Suspicious Traffic
- DDoS Attack

---

### Dashboard

Displays

- Live Packet Count
- Packets Per Second
- SYN Rate
- Attack Type
- Source IP
- Detection Latency

---

### Logging

Detected events are exported to CSV.

Example fields

- Timestamp
- Source IP
- Destination IP
- Attack Type
- Detection Method
- Severity
