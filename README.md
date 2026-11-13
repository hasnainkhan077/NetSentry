# NetSentry – Network Security Assessment System

## About the Project
NetSentry is a centralized network security assessment system designed for small organizations and educational institutions. It provides administrators with a dashboard to manage network devices, discover active hosts, identify unregistered devices, review security findings, and generate PDF assessment reports.

## Problem Statement
Small organizations may lack accessible tools to maintain visibility over their network devices. Without organized device inventory and regular network checks, administrators may struggle to identify unfamiliar devices and track network changes.

## Key Features
- Administrator login and dashboard
- Network device registration and management
- Authorized network discovery using Nmap
- Comparison of discovered devices with registered inventory
- Identification of unregistered devices
- Security findings and alerts
- Assessment history
- Downloadable PDF security assessment reports

## Technology Stack
- **Programming Language:** Python
- **Web Framework:** Flask
- **Database:** SQLite
- **Network Discovery:** Nmap
- **Frontend:** HTML5 and CSS3
- **PDF Reports:** ReportLab

## Project Scope
NetSentry is a prototype focused on network visibility, device inventory management, and basic security assessment. It is not a full vulnerability scanner or continuous network monitoring platform.

## Running the Project Locally
1. Install Python and Nmap.
2. Clone or download this repository.
3. Create and activate a Python virtual environment.
4. Install the required packages:

   `pip install -r requirements.txt`

5. Configure the administrator account using the project's setup instructions.
6. Start the application:

   `python app.py`

7. Open `http://127.0.0.1:5000` in your browser.

**Note:** Use NetSentry only on networks you own or have permission to assess.

## Developed By
Muhammad Hasnain Khan

YE Hackathon 2026 – Cybersecurity Track
