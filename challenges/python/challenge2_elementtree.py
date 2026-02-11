#!/usr/bin/env python3
"""
XXE CTF Challenge - Python ElementTree (Whitebox)
Difficulty: Medium
Flag Location: /app/secrets/admin_token.txt

Description:
This API processes XML configuration files. The application uses Python's
built-in xml.etree.ElementTree, which has some protections but can still
be vulnerable in certain configurations.

Vulnerability: Using deprecated defusedxml workaround incorrectly
"""

from flask import Flask, request, jsonify
import xml.etree.ElementTree as ET
import os

app = Flask(__name__)

# Setup challenge environment
os.makedirs('/app/secrets', exist_ok=True)
FLAG_CONTENT = "XXE{3l3m3ntTr33_n0t_s0_s4f3}"
with open('/app/secrets/admin_token.txt', 'w') as f:
    f.write(FLAG_CONTENT)

# Add some internal service simulation
with open('/app/secrets/database.conf', 'w') as f:
    f.write("db_password=super_secret_123\ndb_host=internal-db.local")

@app.route('/')
def index():
    return """
    <html>
    <head><title>Configuration Manager</title></head>
    <body>
        <h1>XML Configuration Manager</h1>
        <p>Upload your configuration in XML format</p>
        <form action="/upload-config" method="POST">
            <textarea name="config" rows="15" cols="60" placeholder="XML configuration..."></textarea><br>
            <input type="submit" value="Upload Configuration">
        </form>
        <hr>
        <h3>Example Configuration:</h3>
        <pre>
&lt;?xml version="1.0"?&gt;
&lt;config&gt;
    &lt;setting name="timeout"&gt;30&lt;/setting&gt;
    &lt;setting name="retries"&gt;3&lt;/setting&gt;
&lt;/config&gt;
        </pre>
    </body>
    </html>
    """

@app.route('/upload-config', methods=['POST'])
def upload_config():
    """
    VULNERABLE: Attempts to use ElementTree "safely" but misses edge cases
    """
    try:
        config_xml = request.form.get('config', '')
        
        if not config_xml:
            return jsonify({'error': 'No configuration provided'}), 400
        
        # VULNERABLE: While ElementTree has protections, this approach has issues
        # Using ET.fromstring without additional safeguards
        root = ET.fromstring(config_xml)
        
        # Process configuration
        settings = {}
        for setting in root.findall('.//setting'):
            name = setting.get('name')
            value = setting.text
            if name and value:
                settings[name] = value
        
        result = {
            'status': 'Configuration uploaded successfully',
            'settings_count': len(settings),
            'settings': settings
        }
        
        return jsonify(result)
        
    except ET.ParseError as e:
        return jsonify({'error': f'Configuration parsing error: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': f'Error processing configuration: {str(e)}'}), 500

@app.route('/info')
def info():
    return jsonify({
        'parser': 'xml.etree.ElementTree',
        'python_version': os.sys.version,
        'hint': 'ElementTree is mostly safe, but look for edge cases'
    })

if __name__ == '__main__':
    print("=" * 60)
    print("XXE CTF Challenge - Python ElementTree (Whitebox)")
    print("=" * 60)
    print("Server starting on http://localhost:8111")
    print("Flag location: /app/secrets/admin_token.txt")
    print("Hint: ElementTree has protections, but not all Python XML parsers do")
    print("=" * 60)
    app.run(host='0.0.0.0', port=8111, debug=False)