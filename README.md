# Network Intrusion Detection System (NIDS)

A rule-based Network Intrusion Detection System designed to monitor live network traffic, analyze packets, and detect suspicious or malicious activities using predefined signatures stored in a database.

### Contributors
- Sahana Sukumaran [sahana-sukumaran](https://github.com/sahana-sukumaran/)
- Sai Nithya Maheswari PK [Sai-Nithya-7](https://github.com/Sai-Nithya-7/)

##  Overview
This project implements a lightweight NIDS that captures real-time network packets, evaluates them against intrusion detection rules stored in a database, and generates alerts based on severity. 

##  Features
- Live network traffic monitoring  
- Signature-based intrusion detection  
- SQL-driven rule evaluation engine  
- Severity-based alert generation  
- Active host discovery on the network  

##  Attacks Detected
- Port scanning activities  
- Brute-force attempts  
- Protocol abuse  
- Suspicious data exfiltration patterns  

##  Technologies Used
- Python  
- Scapy – Packet capture and analysis  
- Nmap – Active host discovery and scanning  
- SQL – Rule storage and evaluation  
- Multithreading – Concurrent packet capture and processing  

##  System Architecture
- Capture live network packets using Scapy  
- Extract relevant packet features  
- Match packet data against SQL-stored intrusion rules  
- Classify activity based on rule severity  
- Generate alerts for detected threats  

##  How It Works
- Network packets are captured in real time.  
- Each packet is analyzed against predefined intrusion rules stored in a database.  
- If a rule is triggered, an alert is generated with the corresponding severity level.  
- Multiple detection tasks run concurrently using multithreading for better performance.

##  Setup & Usage
1. Clone the repository
   ```bash
   git clone https://github.com/sahana-sukumaran/Network-Intrusion-Detection-System.git
   cd Network-Intrusion-Detection-System
2. Install dependencies
   ```bash
   pip install -r requirements.txt
3. Run the NIDS
   ```bash
   sudo python monitor.py
Note: Root privileges are required for packet capture and network scanning.

##  Configuration & Security
- Sensitive configuration such as IP ranges, network interfaces, and credentials are stored in a `.env` file  
- A `.env.example` file is provided to indicate required environment variables without exposing real values  
