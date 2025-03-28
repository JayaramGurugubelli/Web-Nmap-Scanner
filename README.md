# Web-Nmap-Scanner
This is a Nmap Scanner Web Application built using Python's Flask web framework. The app allows users to scan IP addresses, URLs, and specific ports using Nmap, and displays the scan results in a web interface
1. Backend (Python + Flask)

This section handles the server-side logic, including initializing the Nmap PortScanner, handling scan requests, and rendering results.
import os
import nmap
import socket
from flask import Flask, render_template_string, request

app = Flask(__name__)

# Initialize the Nmap PortScanner object
scanner = nmap.PortScanner()

# Function to scan an IP address
def scan_ip(ip):
    try:
        scanner.scan(ip, '22,80,443')  # Scan specific common ports
        scan_results = {}
        scan_results['info'] = str(scanner[ip])
        if 'osmatch' in scanner[ip]:
            scan_results['os'] = str(scanner[ip]['osmatch'])
        else:
            scan_results['os'] = "OS detection failed"
        scan_results['ports'] = str(scanner[ip].all_tcp())
        return scan_results
    except Exception as e:
        return {'error': str(e)}

# Function to scan a URL
def scan_url(url):
    try:
        # Resolve URL to IP using socket
        ip = socket.gethostbyname(url)
        if ip:
            return scan_ip(ip)
        else:
            return {'error': 'Failed to resolve URL'}
    except socket.gaierror:
        return {'error': 'Failed to resolve URL'}
    except Exception as e:
        return {'error': str(e)}

# Function to scan specific ports on an IP
def scan_ports(ip, ports):
    try:
        port_range = ",".join(ports.split(","))
        scanner.scan(ip, port_range)
        scan_results = {}
        scan_results['info'] = str(scanner[ip])
        scan_results['ports'] = str(scanner[ip].all_tcp())
        return scan_results
    except Exception as e:
        return {'error': str(e)}

# Flask Routes for Handling Requests
@app.route('/')
def home():
    return render_template_string(index_html)

@app.route('/scan', methods=['POST'])
def scan():
    scan_type = request.form['scan_type']
    if scan_type == '1':  # Scan IP
        ip = request.form['ip']
        results = scan_ip(ip)
    elif scan_type == '2':  # Scan URL
        url = request.form['url']
        results = scan_url(url)
    elif scan_type == '3':  # Scan specific ports on an IP
        ip = request.form['ip']
        ports = request.form['ports']
        results = scan_ports(ip, ports)
    else:
        results = {'error': 'Invalid choice'}
    
    return render_template_string(result_html, results=results)

if __name__ == '__main__':
    app.run(debug=True)
2. Frontend (HTML, CSS, JavaScript)

This section provides the user interface that interacts with the backend. It includes forms, buttons, and results rendering, as well as some client-side logic for showing and hiding different input fields based on the selected scan type.
<!-- index.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nmap Scanner</title>
    <style>
        /* CSS Styles for the frontend */
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f9;
            color: #333;
            margin: 0;
            padding: 0;
        }

        header {
            background-color: #007BFF;
            color: white;
            padding: 15px 0;
            text-align: center;
        }

        h1 {
            margin: 0;
            font-size: 2em;
        }

        .container {
            width: 50%;
            margin: 30px auto;
            padding: 20px;
            background-color: #ffffff;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }

        label {
            font-size: 1.1em;
        }

        input[type="text"] {
            width: 100%;
            padding: 10px;
            margin-bottom: 15px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }

        input[type="radio"] {
            margin-right: 10px;
        }

        button {
            background-color: #007BFF;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            width: 100%;
        }

        button:hover {
            background-color: #0056b3;
        }

        /* Marquee Styles */
        marquee {
            color: #FFFFFF;
            background-color: #333;
            font-size: 1.2em;
            padding: 10px 0;
            margin-bottom: 20px;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <header>
        <h1>Nmap Scanner</h1>
    </header>

    <!-- Marquee Section -->
    <marquee behavior="scroll" direction="left">Welcome to the Nmap Scanner! Scan your IPs or URLs and get the results quickly.</marquee>

    <div class="container">
        <form action="/scan" method="post">
            <label for="scan_type">Choose scan type:</label><br>
            <input type="radio" name="scan_type" value="1" required> Scan an IP address<br>
            <input type="radio" name="scan_type" value="2" required> Scan a URL<br>
            <input type="radio" name="scan_type" value="3" required> Scan specific ports on an IP<br><br>

            <div id="ip_input">
                <label for="ip">Enter IP address:</label><br>
                <input type="text" name="ip" id="ip" placeholder="e.g., 192.168.1.1"><br><br>
            </div>

            <div id="url_input" style="display:none;">
                <label for="url">Enter URL:</label><br>
                <input type="text" name="url" id="url" placeholder="e.g., example.com"><br><br>
            </div>

            <div id="ports_input" style="display:none;">
                <label for="ports">Enter ports (comma-separated):</label><br>
                <input type="text" name="ports" id="ports" placeholder="e.g., 22,80,443"><br><br>
            </div>

            <button type="submit">Start Scan</button>
        </form>
    </div>

    <script>
        // Show/hide fields based on selected scan type
        document.querySelectorAll('input[name="scan_type"]').forEach((radio) => {
            radio.addEventListener('change', function() {
                if (
Project Description: Nmap Scanner Web Application

The Nmap Scanner Web Application is a Python-based web tool designed to allow users to scan IP addresses, URLs, and specific ports on a network. The application leverages the powerful Nmap tool, which is widely used for network discovery and security auditing. The web interface is built using Flask, a lightweight Python web framework, combined with HTML, CSS, and JavaScript to create an interactive, user-friendly experience.

The primary objective of this project is to provide a simple way to perform network scans through a web browser, making Nmap's powerful capabilities more accessible to users who may not be familiar with command-line interfaces. Users can initiate scans by entering an IP address, a URL, or specifying a list of ports for an IP address. The application uses Nmap's scanning features to identify open ports, the operating system of the target, and additional details about the scanned host.
