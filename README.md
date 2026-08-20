#  Mini-SIEM v2.0 (Active Defense & Log Analysis System)

##  Overview
Mini-SIEM is a custom-built, lightweight Security Information and Event Management (SIEM) tool written entirely in Python. Designed for Linux environments (Ubuntu), it acts as an Active Intrusion Prevention System (IPS) by dynamically reading system logs, detecting anomalies, and automatically banning malicious actors using UFW.

##  Key Features
*   **Live Tail Engine:** Continuously monitors `/var/log/auth.log` in real-time without memory bloat.
*   **Dynamic Rule Engine:** Uses a flexible `rules.json` file powered by Regex to detect threats (SSH Brute Force, SQL Injection, Port Scans, etc.).
*   **Active Defense (IPS):** Integrates directly with Linux UFW. If an IP violates rules 3 times, it automatically issues a network-level ban.
*   **Threat Database:** Logs all parsed alerts into a structured `alerts.json` format, mapped to **MITRE ATT&CK** framework IDs.
*   **Shift-End Reporting:** Includes an independent `report.py` module to generate a clean, statistical dashboard of all detected threats and aggressive IP addresses.

##  Tech Stack
*   **Language:** Python 3
*   **OS/Environment:** Linux (Ubuntu 22.04)
*   **Security Tools:** UFW (Uncomplicated Firewall), Regex
*   **Data Format:** JSON

##  Why I Built This?
I built this project to move beyond theoretical SOC analysis. Instead of just reading logs on platforms, I wanted to understand the core mechanics of how a SIEM parses data and how an IPS takes automated action against threats.
