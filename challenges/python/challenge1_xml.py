#!/usr/bin/env python3
"""
XXE CTF Challenge - Python lxml (Whitebox)
Difficulty: Easy
Flag Location: /tmp/flag.txt

Description:
This is a simple XML processing API that parses user-submitted XML documents.
Your goal is to exploit the XXE vulnerability to read the flag file.

Vulnerability: lxml parser configured without security restrictions
"""

from flask import Flask, request, jsonify
from lxml import etree
import os

app = Flask(__name__)

# Create flag file for the challenge
FLAG_CONTENT = "XXE{lxml_pr0tect_y0ur_p4rs3r}"
os.makedirs('/tmp', exist_ok=True)
with open('/tmp/flag.txt', 'w') as f:
    f.write(FLAG_CONTENT)

@app.route('/')
def index():
    return """
    <html>
    <head><title>XML Parser Service</title></head>
    <body>
        <h1>XML Document Parser</h1>
        <p>Submit XML documents for processing</p>
        <form action="/parse" method="POST">
            <textarea name="xml" rows="10" cols="50" placeholder="Enter XML here..."></textarea><br>
            <input type="submit" value="Parse XML">
        </form>
        <hr>
        <h3>Example XML:</h3>
        <pre>
&lt;?xml version="1.0"?&gt;
&lt;data&gt;
    &lt;user&gt;Alice&lt;/user&gt;
    &lt;message&gt;Hello World&lt;/message&gt;
&lt;/data&gt;
        </pre>
    </body>
    </html>
    """

@app.route('/parse', methods=['POST'])
def parse_xml():
    """
        VULNERABLE: This endpoint parses XML without disabling external entities
    """

    try:
        xml_data = request.form.get('xml', '')
        
        if not xml_data:
            return jsonify({'error': 'No XML data provided'}), 400
        
        # VULNERABLE: Using lxml parser with default settings
        # resolve_entities=True allows external entity resolution
        parser = etree.XMLParser(resolve_entities=True)
        
        # Parse the XML - XXE vulnerability here!
        tree = etree.fromstring(xml_data.encode(), parser)
        
        # Extract and return data
        result = {
            'status': 'success',
            'parsed': True,
            'content': etree.tostring(tree, encoding='unicode')
        }
        
        return jsonify(result)
        
    except etree.XMLSyntaxError as e:
        return jsonify({'error': f'XML parsing error: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'parser': 'lxml'})

if __name__ == '__main__':
    print("=" * 60)
    print("XXE CTF Challenge - Python lxml (Whitebox)")
    print("=" * 60)
    print("Server starting on http://localhost:8110")
    print("Flag location: /tmp/flag.txt")
    print("Hint: Look at the lxml parser configuration")
    print("=" * 60)
    app.run(host='0.0.0.0', port=8110, debug=False)
