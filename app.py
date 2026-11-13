
import os
import sqlite3
import secrets
import ipaddress
import subprocess
import xml.etree.ElementTree as ET

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, send_file
)
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from werkzeug.security import check_password_hash


# Create Flask application
app = Flask(__name__)

# Temporary secret key for local development
app.secret_key = secrets.token_hex(32)

# Database location
DB_PATH = os.path.join(app.root_path, "netsentry.db")


# Initialize database tables
def initialize_database():

    connection = sqlite3.connect(DB_PATH)

    # Registered Devices Table
    connection.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_name TEXT NOT NULL,
            ip_address TEXT UNIQUE NOT NULL,
            device_type TEXT NOT NULL,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Discovered Devices Table
    connection.execute("""
        CREATE TABLE IF NOT EXISTS discovered_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            mac_address TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Alerts and Logs Table
    connection.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            ip_address TEXT,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'New'
        )
    """)

    # Assessment History Table
    connection.execute("""
        CREATE TABLE IF NOT EXISTS assessment_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            registered_count INTEGER NOT NULL,
            discovered_count INTEGER NOT NULL,
            finding_count INTEGER NOT NULL,
            assessment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


initialize_database()


# Network Discovery Function
def discover_network_devices(network_range):

    # Validate the supplied network
    try:
        network = ipaddress.ip_network(
            network_range,
            strict=False
        )
    except ValueError:
        raise ValueError("Please enter a valid network range.")

    # Only allow small, private IPv4 networks
    if (
        network.version != 4
        or not network.is_private
        or network.num_addresses > 256
    ):
        raise ValueError(
            "Only private IPv4 networks with up to 256 addresses are allowed."
        )

    # Run Nmap host discovery and request XML output
    command = [
        "nmap",
        "-sn",
        "-oX",
        "-",
        str(network)
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=60
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or "Nmap discovery failed."
        )

    # Read Nmap XML results
    root = ET.fromstring(result.stdout)
    discovered_devices = []

    for host in root.findall("host"):

        status = host.find("status")

        if status is None or status.get("state") != "up":
            continue

        address = host.find("address[@addrtype='ipv4']")
        mac = host.find("address[@addrtype='mac']")

        if address is not None:
            discovered_devices.append({
                "ip_address": address.get("addr"),
                "mac_address": (
                    mac.get("addr")
                    if mac is not None
                    else "Unavailable"
                )
            })

    return discovered_devices


# Home page
@app.route("/")
def home():

    if session.get("admin_id"):
        return redirect(url_for("dashboard"))

    return render_template("login.html")


# Administrator login
@app.route("/login", methods=["POST"])
def login():

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    # Find administrator in database
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    try:
        admin = connection.execute(
            "SELECT * FROM admin WHERE username = ?",
            (username,)
        ).fetchone()
    finally:
        connection.close()

    # Verify password
    if admin and check_password_hash(
        admin["password_hash"], password
    ):
        session.clear()
        session["admin_id"] = admin["id"]
        session["admin_username"] = admin["username"]

        return redirect(url_for("dashboard"))

    return render_template(
        "login.html",
        error="Invalid username or password."
    )




# Protected dashboard
@app.route("/dashboard")
def dashboard():

    if not session.get("admin_id"):
        return redirect(url_for("home"))

    # Connect to the database
    connection = sqlite3.connect(DB_PATH)

    # Count registered devices
    device_count = connection.execute(
        "SELECT COUNT(*) FROM devices"
    ).fetchone()[0]

    # Count recorded security alerts
    alert_count = connection.execute(
        "SELECT COUNT(*) FROM alerts"
    ).fetchone()[0]

    # Count completed assessments
    assessment_count = connection.execute(
        "SELECT COUNT(*) FROM assessment_history"
    ).fetchone()[0]

    connection.close()

    return render_template(
        "dashboard.html",
        admin_username=session["admin_username"],
        device_count=device_count,
        alert_count=alert_count,
        assessment_count=assessment_count
    )


# Device Management
@app.route("/devices", methods=["GET", "POST"])
def devices():

    # Protect this page from unauthorized access
    if not session.get("admin_id"):
        return redirect(url_for("home"))

    message = ""

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    if request.method == "POST":

        device_name = request.form.get(
            "device_name", ""
        ).strip()

        ip_address = request.form.get(
            "ip_address", ""
        ).strip()

        device_type = request.form.get(
            "device_type", ""
        ).strip()

        if not device_name or not ip_address or not device_type:
            message = "Please fill in all fields."

        else:
            try:
                ipaddress.IPv4Address(ip_address)

            except ValueError:
                message = "Please enter a valid IPv4 address."

            else:
                try:
                    connection.execute(
                        """
                        INSERT INTO devices
                        (device_name, ip_address, device_type)
                        VALUES (?, ?, ?)
                        """,
                        (device_name, ip_address, device_type)
                    )

                    connection.commit()
                    message = "Device registered successfully!"

                except sqlite3.IntegrityError:
                    message = "This IP address is already registered."

    registered_devices = connection.execute(
        "SELECT * FROM devices ORDER BY id DESC"
    ).fetchall()

    connection.close()

    return render_template(
        "devices.html",
        devices=registered_devices,
        message=message
    )


# Network Discovery
@app.route("/discovery", methods=["GET", "POST"])
def discovery():

    if not session.get("admin_id"):
        return redirect(url_for("home"))

    discovered_devices = []
    message = ""
    network_range = ""
    scan_completed = False
    new_devices = []
    current_devices = []

    if request.method == "POST":

        network_range = request.form.get(
            "network_range", ""
        ).strip()

        try:
            # Discover devices on the network
            current_devices = discover_network_devices(
                network_range
            )

            # Connect to the database
            connection = sqlite3.connect(DB_PATH)

            # Get previously discovered IP addresses
            previous_ips = {
                row[0] for row in connection.execute(
                    "SELECT ip_address FROM discovered_devices"
                ).fetchall()
            }

            # Get registered device IP addresses
            registered_ips = {
                row[0] for row in connection.execute(
                    "SELECT ip_address FROM devices"
                ).fetchall()
            }

            # Identify newly discovered IP addresses
            new_devices = [
                device for device in current_devices
                if device["ip_address"] not in previous_ips
            ]

            # Save or update discovered devices
            for device in current_devices:
                connection.execute("""
                    INSERT INTO discovered_devices
                    (ip_address, mac_address)
                    VALUES (?, ?)
                    ON CONFLICT(ip_address) DO UPDATE SET
                        mac_address = excluded.mac_address,
                        last_seen = CURRENT_TIMESTAMP
                """, (
                    device["ip_address"],
                    device["mac_address"]
                ))

            # Generate alerts for new unregistered devices
            for device in new_devices:

                ip_address = device["ip_address"]

                if ip_address not in registered_ips:

                    connection.execute("""
                        INSERT INTO alerts
                        (
                            alert_type,
                            ip_address,
                            severity,
                            description
                        )
                        VALUES (?, ?, ?, ?)
                    """, (
                        "New Unregistered Device",
                        ip_address,
                        "Medium",
                        (
                            f"A newly discovered device with IP "
                            f"{ip_address} is not registered in "
                            f"the device inventory. Administrator "
                            f"review is recommended."
                        )
                    ))

            connection.commit()
            connection.close()

            scan_completed = True

            message = (
                f"Discovery completed! "
                f"{len(current_devices)} devices found."
            )

        except (
            ValueError,
            RuntimeError,
            subprocess.TimeoutExpired,
            ET.ParseError
        ) as error:

            message = str(error)

    # Retrieve saved discovery history
    connection = sqlite3.connect(DB_PATH)

    # Get registered device IP addresses
    registered_ips = {
        row[0] for row in connection.execute(
            "SELECT ip_address FROM devices"
        ).fetchall()
    }

    # Get all previously discovered devices
    saved_devices = connection.execute("""
        SELECT ip_address, mac_address, first_seen, last_seen, id
        FROM discovered_devices
        ORDER BY last_seen DESC
    """).fetchall()

    connection.close()

    # IP addresses found in the latest successful scan
    current_ips = {
        device["ip_address"] for device in current_devices
    } if scan_completed else set()

    # Prepare saved records for the webpage
    for device in saved_devices:

        ip_address = device[0]

        discovered_devices.append({
            "ip_address": ip_address,
            "mac_address": device[1],
            "first_seen": device[2],
            "last_seen": device[3],
            "id": device[4],

            "inventory_status": (
                "Registered"
                if ip_address in registered_ips
                else "Not in Inventory"
            ),

            "availability_status": (
                "Online"
                if ip_address in current_ips
                else "Offline"
                if scan_completed
                else "Not checked"
            )
        })

    return render_template(
        "discovery.html",
        discovered_devices=discovered_devices,
        message=message,
        network_range=network_range,
        new_devices=new_devices,
        scan_completed=scan_completed
    )



# Dismiss an unregistered discovered device
@app.route("/dismiss-device/<int:device_id>", methods=["POST"])
def dismiss_device(device_id):

    # Protect this action from unauthorized access
    if not session.get("admin_id"):
        return redirect(url_for("home"))

    connection = sqlite3.connect(DB_PATH)

    # Delete only if the device is not registered
    connection.execute("""
        DELETE FROM discovered_devices
        WHERE id = ?
        AND ip_address NOT IN (
            SELECT ip_address FROM devices
        )
    """, (device_id,))

    connection.commit()
    connection.close()

    return redirect(url_for("discovery"))


# Security Assessment
@app.route("/assessment", methods=["GET", "POST"])
def assessment():

    if not session.get("admin_id"):
        return redirect(url_for("home"))

    findings = []
    assessment_run = False

    connection = sqlite3.connect(DB_PATH)

    # Retrieve registered devices
    registered_devices = connection.execute("""
        SELECT device_name, ip_address, device_type
        FROM devices
    """).fetchall()

    # Retrieve discovered devices
    discovered_devices = connection.execute("""
        SELECT ip_address, mac_address
        FROM discovered_devices
    """).fetchall()

    connection.close()

    # Compare registered and discovered IP addresses
    registered_ips = {
        device[1] for device in registered_devices
    }

    discovered_ips = {
        device[0] for device in discovered_devices
    }

    if request.method == "POST":

        assessment_run = True

        # Identify discovered devices not in inventory
        for device in discovered_devices:

            ip_address = device[0]

            if ip_address not in registered_ips:

                findings.append({
                    "title": "Unregistered Network Device",
                    "ip_address": ip_address,
                    "severity": "Medium",
                    "description": (
                        "This IP address was discovered "
                        "but is not registered in the device inventory."
                    ),
                    "recommendation": (
                        "Verify the device and register it "
                        "if it is authorized."
                    )
                })

        
        # Identify registered devices never seen in discovery history
        for device in registered_devices:

            device_name = device[0]
            ip_address = device[1]

            if ip_address not in discovered_ips:

                findings.append({
                    "title": "Device Not Previously Detected",
                    "ip_address": ip_address,
                    "severity": "Low",
                    "description": (
                        f"{device_name} has not appeared "
                        "in the saved discovery history."
                    ),
                    "recommendation": (
                        "Verify the device's network connection "
                        "and perform an authorized discovery scan."
                    )
                })

        # Save assessment results in history
        connection = sqlite3.connect(DB_PATH)

        connection.execute("""
            INSERT INTO assessment_history
            (
                registered_count,
                discovered_count,
                finding_count
            )
            VALUES (?, ?, ?)
        """, (
            len(registered_devices),
            len(discovered_devices),
            len(findings)
        ))

        connection.commit()
        connection.close()

        # Retrieve assessment history
    connection = sqlite3.connect(DB_PATH)

    assessment_history = connection.execute("""
        SELECT
            id,
            assessment_date,
            registered_count,
            discovered_count,
            finding_count
        FROM assessment_history
        ORDER BY assessment_date DESC
    """).fetchall()

    connection.close()

    return render_template(
        "assessment.html",
        findings=findings,
        assessment_run=assessment_run,
        registered_count=len(registered_devices),
        discovered_count=len(discovered_devices),
        finding_count=len(findings),
        assessment_history=assessment_history
    )


# Alerts and Logs
@app.route("/alerts")
def alerts():

    if not session.get("admin_id"):
        return redirect(url_for("home"))

    # Connect to the database
    connection = sqlite3.connect(DB_PATH)

    # Retrieve saved alerts
    saved_alerts = connection.execute("""
        SELECT
            id,
            alert_type,
            ip_address,
            severity,
            description,
            created_at,
            status
        FROM alerts
        ORDER BY created_at DESC
    """).fetchall()

    connection.close()

    return render_template(
        "alerts.html",
        alerts=saved_alerts
    )


# Administrator logout
@app.route("/logout", methods=["POST"])
def logout():

    session.clear()

    return redirect(url_for("home"))

# Reports Page
@app.route("/reports")
def reports():

    if not session.get("admin_id"):
        return redirect(url_for("home"))

    return render_template(
        "reports.html",
        admin_username=session["admin_username"]
    )


# Download PDF Security Assessment Report
@app.route("/reports/download", methods=["POST"])
def download_report():

    if not session.get("admin_id"):
        return redirect(url_for("home"))

    # Retrieve device information
    connection = sqlite3.connect(DB_PATH)

    registered_devices = connection.execute("""
        SELECT device_name, ip_address, device_type
        FROM devices
    """).fetchall()

    discovered_devices = connection.execute("""
        SELECT ip_address, mac_address
        FROM discovered_devices
    """).fetchall()

    connection.close()

    # Compare registered and discovered devices
    registered_ips = {
        device[1] for device in registered_devices
    }

    discovered_ips = {
        device[0] for device in discovered_devices
    }

    findings = []

    # Find unregistered devices
    for device in discovered_devices:

        ip_address = device[0]

        if ip_address not in registered_ips:

            findings.append({
                "title": "Unregistered Network Device",
                "ip_address": ip_address,
                "severity": "Medium",
                "description": (
                    "This device was discovered but is not "
                    "registered in the device inventory."
                ),
                "recommendation": (
                    "Verify the device and register it "
                    "if it is authorized."
                )
            })

    # Find registered devices not seen in discovery history
    for device in registered_devices:

        device_name = device[0]
        ip_address = device[1]

        if ip_address not in discovered_ips:

            findings.append({
                "title": "Device Not Previously Detected",
                "ip_address": ip_address,
                "severity": "Low",
                "description": (
                    f"{device_name} has not appeared "
                    "in the saved discovery history."
                ),
                "recommendation": (
                    "Verify the device's network connection "
                    "and perform an authorized discovery scan."
                )
            })

    # Create PDF in memory
    buffer = BytesIO()

    pdf = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        title="NetSentry Security Assessment Report",
        author="NetSentry"
    )

    styles = getSampleStyleSheet()

    story = []

    # Report title
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        textColor=colors.HexColor("#12345A"),
        alignment=TA_CENTER,
        fontSize=20
    )

    story.append(
        Paragraph("NetSentry Security Assessment Report", title_style)
    )

    story.append(Spacer(1, 20))

    # Report summary
    story.append(Paragraph("Assessment Summary", styles["Heading2"]))

    summary_data = [
        ["Report Information", "Value"],
        ["Registered Devices", str(len(registered_devices))],
        ["Discovered Devices", str(len(discovered_devices))],
        ["Security Findings", str(len(findings))]
    ]

    summary_table = Table(summary_data, colWidths=[230, 230])

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12345A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
    ]))

    

    story.append(summary_table)
    story.append(Spacer(1, 20))

    # Registered Devices
    story.append(
        Paragraph("Registered Devices", styles["Heading2"])
    )

    if registered_devices:

        registered_data = [
            ["Device Name", "IP Address", "Device Type"]
        ]

        for device in registered_devices:
            registered_data.append([
                str(device[0]),
                str(device[1]),
                str(device[2])
            ])

        registered_table = Table(
            registered_data,
            colWidths=[160, 140, 160],
            repeatRows=1
        )

        registered_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12345A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
        ]))

        
        story.append(registered_table)
    
    else:
        story.append(
            Paragraph(
                "No registered devices found.",
                styles["Normal"]
            )
        )

    story.append(Spacer(1, 20))

    # Discovered Devices
    story.append(
        Paragraph("Discovered Devices", styles["Heading2"])
    )

    if discovered_devices:

        discovered_data = [
            ["IP Address", "MAC Address"]
        ]

        for device in discovered_devices:
            discovered_data.append([
                str(device[0]),
                str(device[1])
            ])

        discovered_table = Table(
            discovered_data,
            colWidths=[230, 230],
            repeatRows=1
        )

        discovered_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12345A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
        ]))

        story.append(discovered_table)

    else:
        story.append(
            Paragraph(
                "No discovered devices found.",
                styles["Normal"]
            )
        )

    story.append(Spacer(1, 20))

    # Security findings

    story.append(Paragraph("Security Findings", styles["Heading2"]))

    if findings:

        for index, finding in enumerate(findings, start=1):

            story.append(
                Paragraph(
                    f"<b>{index}. {finding['title']}</b>",
                    styles["Heading3"]
                )
            )

            story.append(
                Paragraph(
                    f"<b>IP Address:</b> {finding['ip_address']}",
                    styles["Normal"]
                )
            )

            story.append(
                Paragraph(
                    f"<b>Severity:</b> {finding['severity']}",
                    styles["Normal"]
                )
            )

            story.append(
                Paragraph(
                    f"<b>Description:</b> {finding['description']}",
                    styles["Normal"]
                )
            )

            story.append(
                Paragraph(
                    f"<b>Recommended Action:</b> "
                    f"{finding['recommendation']}",
                    styles["Normal"]
                )
            )

            story.append(Spacer(1, 12))

    else:

        story.append(
            Paragraph(
                "No security findings were identified "
                "in the current assessment snapshot.",
                styles["Normal"]
            )
        )

    # Report footer information
    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "Generated by NetSentry Network Security Assessment System.",
            styles["Italic"]
        )
    )

    # Generate PDF
    pdf.build(story)

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="NetSentry_Security_Assessment_Report.pdf",
        mimetype="application/pdf"
    )


# Run application
if __name__ == "__main__":
    app.run(debug=True)
