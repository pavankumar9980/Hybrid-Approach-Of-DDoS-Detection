from flask import Flask, request, jsonify, send_file
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from flask_cors import CORS
import joblib
import pandas as pd
import threading
import time
from scapy.all import sniff, TCP, UDP, ICMP, IP
from collections import defaultdict
import csv
from io import StringIO

app = Flask(__name__)
CORS(app)
app.config["JWT_SECRET_KEY"] = "pavan-perfect-2025"
jwt = JWTManager(app)

# Load models
try:
    scaler = joblib.load("preprocessor_lrhr.pkl")
    iso = joblib.load("iso_forest_lrhr.pkl")
    rf = joblib.load("rf_clf_lrhr.pkl")
except:
    print("Models not found — using rule-based only")

current_stats = {
    "result": "Normal Traffic",
    "attack_type": "Normal Traffic",
    "confidence": 0,
    "pkt_rate": 0,
    "syn_rate": 0,
    "udp_rate": 0,
    "icmp_rate": 0,
    "ack_rate": 0,
    "attacker_ip": "None"
}

# UNLIMITED PACKETS
captured_packets = []

def calculate_traffic():
    global current_stats, captured_packets
    while True:
        packets = sniff(timeout=1)
        pkt_count = len(packets)
        syn = ack = udp = icmp = 0
        src_ips = defaultdict(int)

        for p in packets:
            if IP in p:
                src_ips[p[IP].src] += 1
                if TCP in p:
                    f = p[TCP].flags
                    if f & 0x02: syn += 1
                    if f & 0x10: ack += 1
                elif UDP in p: udp += 1
                elif ICMP in p: icmp += 1

                captured_packets.append({
                    "timestamp": time.strftime("%H:%M:%S"),
                    "source_ip": p[IP].src,
                    "dest_ip": p[IP].dst,
                    "protocol": "TCP" if TCP in p else "UDP" if UDP in p else "ICMP" if ICMP in p else "Other",
                    "size": len(p),
                    "flags": str(p[TCP].flags) if TCP in p else "N/A"
                })

        attacker_ip = max(src_ips, key=src_ips.get, default="None") if src_ips else "None"

        attack_type = "Normal Traffic"
        confidence = 50
        if syn > 50:
            attack_type = "SYN Flood"
            confidence = 99
        elif ack > 100:
            attack_type = "ACK Flood"
            confidence = 98
        elif udp > 80:
            attack_type = "UDP Flood"
            confidence = 98
        elif icmp > 70:
            attack_type = "ICMP Flood"
            confidence = 97
        elif pkt_count > 500:
            attack_type = "HTTP/Volume Flood"
            confidence = 96
        elif pkt_count > 200 and syn < 10:
            attack_type = "Slowloris / Low-Rate DDoS"
            confidence = 94

        result = "ALERT: Attack Detected" if attack_type != "Normal Traffic" else "Normal Traffic"

        current_stats = {
            "result": result,
            "attack_type": attack_type,
            "confidence": confidence,
            "pkt_rate": pkt_count,
            "syn_rate": syn,
            "udp_rate": udp,
            "icmp_rate": icmp,
            "ack_rate": ack,
            "attacker_ip": attacker_ip
        }

threading.Thread(target=calculate_traffic, daemon=True).start()

@app.route('/login', methods=['POST'])
def login():
    if request.json.get('user') == 'demo' and request.json.get('pwd') == 'demo123':
        return jsonify({"token": create_access_token(identity="demo")})
    return jsonify({"msg": "Wrong"}), 401

@app.route('/detect', methods=['GET'])
@jwt_required()
def detect():
    return jsonify(current_stats)

@app.route('/packets', methods=['GET'])
@jwt_required()
def get_packets():
    return jsonify(captured_packets)

@app.route('/download_packets', methods=['GET'])
def download_packets():  # PUBLIC — EASY DOWNLOAD AS CSV
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Size', 'Flags'])
    for pkt in captured_packets:
        cw.writerow([pkt['timestamp'], pkt['source_ip'], pkt['dest_ip'], pkt['protocol'], pkt['size'], pkt['flags']])
    si.seek(0)
    return send_file(si, as_attachment=True, download_name='captured_packets.csv', mimetype='text/csv')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)
