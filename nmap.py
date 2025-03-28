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

# HTML Template for index page
index_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nmap Scanner</title>
    <style>
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

        .error {
            color: red;
        }

        .success {
            color: green;
        }

        .results-container {
            margin-top: 20px;
            padding: 20px;
            background-color: #ffffff;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }

        .back-link {
            text-decoration: none;
            background-color: #007BFF;
            color: white;
            padding: 10px 15px;
            border-radius: 4px;
        }

        .back-link:hover {
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
                if (this.value === '1' || this.value === '3') {
                    document.getElementById('ip_input').style.display = 'block';
                    document.getElementById('url_input').style.display = 'none';
                    document.getElementById('ports_input').style.display = this.value === '3' ? 'block' : 'none';
                } else if (this.value === '2') {
                    document.getElementById('ip_input').style.display = 'none';
                    document.getElementById('url_input').style.display = 'block';
                    document.getElementById('ports_input').style.display = 'none';
                }
            });
        });

        // Trigger the change event on page load to display the default state
        document.querySelector('input[name="scan_type"]:checked').dispatchEvent(new Event('change'));
    </script>
</body>
</html>
"""

# HTML Template for results page
result_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Results</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f9;
            color: #333;
            margin: 0;
            padding: 0;
        }
        .container {
            width: 50%;
            margin: 30px auto;
            padding: 20px;
            background-color: #ffffff;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }

        .back-link {
            text-decoration: none;
            background-color: #007BFF;
            color: white;
            padding: 10px 15px;
            border-radius: 4px;
        }

        .back-link:hover {
            background-color: #0056b3;
        }

        .error {
            color: red;
        }

        .success {
            color: green;
        }

        h1 {
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Scan Results</h1>

        {% if results.error %}
            <p class="error">Error: {{ results.error }}</p>
        {% else %}
            <h3>Scan Information:</h3>
            <p>{{ results.info }}</p>

            <h3>OS Detection:</h3>
            <p>{{ results.os }}</p>

            <h3>Open Ports:</h3>
            <p>{{ results.ports }}</p>
        {% endif %}
        
        <br><br>
        <a href="/" class="back-link">Back to Home</a>
    </div>
</body>
</html>
"""

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

