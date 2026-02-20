from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_mail import Mail, Message
import threading
import time
import os
import csv
import hashlib
import requests # Required for ESP32 Gateway
from scapy.all import sniff, TCP, UDP, ICMP, IP, Raw
from collections import defaultdict

app = Flask(__name__)
CORS(app)

# --- CONFIG ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'pavanshetty10101@gmail.com'
app.config['MAIL_PASSWORD'] = 'faguauqjcqmmpsrp'
mail = Mail(app)

MY_IP = "172.29.254.244"
ESP32_IP = "172.29.254.165" # REPLACE with your ESP32's actual IP
captured_packets = []
blockchain_ledger = []

current_stats = {
    "status": "SYSTEM READY",
    "attack_type": "Normal Traffic",
    "confidence": 100,
    "pkt_rate": 0,
    "normal_pps": 0,
    "attack_pps": 0,
    "outgoing_pps": 0,
    "attacker_ip": "None",
    "capture_lat": 0,
    "analysis_lat": 0,
    "total_lat": 0
}

def create_block(data):
    prev_hash = blockchain_ledger[-1]['hash'] if blockchain_ledger else "0"
    block = {"index": len(blockchain_ledger), "timestamp": time.time(), "data": data, "prev_hash": prev_hash}
    block['hash'] = hashlib.sha256(str(block).encode()).hexdigest()
    blockchain_ledger.append(block)

def analyze_traffic():
    # FIX: global declaration MUST be at the top of the function
    global current_stats, captured_packets
    
    while True:
        start_cap = time.perf_counter()
        packets = sniff(timeout=0.05, count=400)
        end_cap = time.perf_counter()
        
        start_ana = time.perf_counter()
        total = len(packets)
        syn = udp = icmp = ack = normal_count = attack_count = outgoing_count = 0
        src_ips = defaultdict(int)
        temp_batch = []

        for p in packets:
            if IP in p:
                s_ip = p[IP].src
                src_ips[s_ip] += 1
                
                is_atk_pkt = False
                proto = "OTHER"

                if s_ip == MY_IP:
                    outgoing_count += 1
                    normal_count += 1 
                else:
                    if TCP in p:
                        proto = "TCP"
                        f = p[TCP].flags
                        if f & 0x02 or f & 0x04: # SYN or RST
                            syn += 1; is_atk_pkt = True 
                        elif f & 0x10: # ACK (Browsing)
                            ack += 1; is_atk_pkt = False 
                    elif UDP in p:
                        proto = "UDP"
                        if len(p) > 1000: udp += 1; is_atk_pkt = True
                    elif ICMP in p:
                        proto = "ICMP"
                        icmp += 1; is_atk_pkt = True

                    if is_atk_pkt: attack_count += 1
                    else: normal_count += 1

                temp_batch.append({
                    "timestamp": time.strftime("%H:%M:%S"),
                    "source_ip": s_ip, "dest_ip": p[IP].dst, "protocol": proto,
                    "size": len(p), "summary": p.summary(),
                    "payload": p[Raw].load.hex() if p.haslayer(Raw) else "No Payload"
                })

        captured_packets = (captured_packets + temp_batch)[-50:]
        
        label = "Normal Traffic"
        conf = 100 
        if syn > 10 or udp > 50 or total > 250:
            label = "Attack Detected"
            conf = 95

        current_stats.update({
            "status": "ATTACK DETECTED" if label != "Normal Traffic" else "SYSTEM READY",
            "attack_type": label, "confidence": conf, "pkt_rate": total * 20,
            "normal_pps": normal_count * 20, "attack_pps": attack_count * 20, 
            "outgoing_pps": outgoing_count * 20,
            "attacker_ip": max(src_ips, key=src_ips.get, default="None") if label != "Normal Traffic" else "None",
            "capture_lat": round((end_cap - start_cap) * 1000, 2),
            "analysis_lat": round((time.perf_counter() - start_ana) * 1000, 2),
            "total_lat": round((time.perf_counter() - start_cap) * 1000, 2)
        })

threading.Thread(target=analyze_traffic, daemon=True).start()

# --- NEW: ESP32 IOT GATEWAY ROUTE ---
@app.route('/iot_gateway')
def iot_gateway():
    """Proxy route to protect the ESP32 server"""
    try:
        if current_stats["status"] == "ATTACK DETECTED":
            return "<h1>SECURITY ALERT</h1><p>IoT Node protected. High traffic blocked.</p>", 503
        
        # Forward request to ESP32
        resp = requests.get(f"http://172.29.254.165/", timeout=1)
        return resp.text
    except:
        return "IoT Hardware Offline", 404

@app.route('/block_ip', methods=['POST'])
def block_ip():
    ip = request.json.get('ip')
    if ip and ip != "None":
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 400

@app.route('/detect')
def detect(): return jsonify(current_stats)

@app.route('/packets')
def get_packets(): return jsonify(captured_packets)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
