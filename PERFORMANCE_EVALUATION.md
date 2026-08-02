# Performance Evaluation

## Objective

Evaluate the performance of the Hybrid DDoS Detection System using both rule-based and Machine Learning detection.

---

# Evaluation Metrics

## Accuracy

Measures the percentage of correctly classified packets.

Accuracy = (TP + TN) / (TP + TN + FP + FN)

---

## Precision

Measures the percentage of predicted attacks that are actually attacks.

Precision = TP / (TP + FP)

---

## Recall

Measures how many actual attacks were detected.

Recall = TP / (TP + FN)

---

## F1 Score

Provides a balance between Precision and Recall.

F1 = 2 × Precision × Recall / (Precision + Recall)

---

## Detection Latency

Time required to detect an attack after packet capture.

Lower latency improves real-time protection.

---

## Throughput

Measures the number of packets processed every second.

Higher throughput indicates better scalability.

---

# Hybrid Detection Workflow

Step 1

Capture packets using Scapy.

↓

Step 2

Extract network features.

↓

Step 3

Apply rule-based detection.

↓

Step 4

Run Machine Learning classification.

↓

Step 5

Combine both results.

↓

Step 6

Generate alert.

↓

Step 7

Store results in CSV.

---

# Advantages

- Fast detection of known attacks.
- Better detection accuracy.
- Reduced false positives.
- Suitable for real-time monitoring.
- Easy integration with web dashboards.

---

# Future Enhancements

- Integration with Splunk SIEM.
- Integration with Wazuh.
- Automated firewall blocking.
- Real-time email notifications.
- Threat Intelligence integration.
- Support for cloud environments.
- Deep Learning based detection.
