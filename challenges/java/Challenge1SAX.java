package com.xxectf.challenges;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.xml.sax.*;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.*;
import java.util.*;

/**
 * XXE CTF Challenge - Java SAX Parser (Whitebox)
 * Difficulty: Easy
 * Flag Location: /tmp/flag.txt
 * 
 * Description:
 * This Spring Boot application provides an XML parsing endpoint using SAX parser.
 * SAX parsers are vulnerable to XXE by default in many Java versions.
 * 
 * Vulnerability: SAXParserFactory without proper security configuration
 */

@SpringBootApplication
@RestController
public class Challenge1SAX {

    private static final String FLAG = "XXE{S4X_p4rs3r_vuln3r4bl3}";

    public static void main(String[] args) throws IOException {
        // Setup flag file
        new File("/tmp").mkdirs();
        try (FileWriter fw = new FileWriter("/tmp/flag.txt")) {
            fw.write(FLAG);
        }
        
        System.out.println("=".repeat(60));
        System.out.println("XXE CTF Challenge - Java SAX Parser (Whitebox)");
        System.out.println("=".repeat(60));
        System.out.println("Server starting on http://localhost:8080");
        System.out.println("Flag location: /tmp/flag.txt");
        System.out.println("Hint: Check SAXParserFactory configuration");
        System.out.println("=".repeat(60));
        
        SpringApplication.run(Challenge1SAX.class, args);
    }

    @GetMapping("/")
    public String index() {
        return """
            <html>
            <head><title>XML Parser - SAX</title></head>
            <body>
                <h1>XML Document Parser (SAX)</h1>
                <p>Submit XML for processing</p>
                <form action="/parse" method="POST">
                    <textarea name="xml" rows="10" cols="50"></textarea><br>
                    <button type="submit">Parse XML</button>
                </form>
                <hr>
                <h3>Example XML:</h3>
                <pre>
&lt;?xml version="1.0"?&gt;
&lt;document&gt;
    &lt;title&gt;Sample Document&lt;/title&gt;
    &lt;content&gt;Hello World&lt;/content&gt;
&lt;/document&gt;
                </pre>
            </body>
            </html>
            """;
    }

    @PostMapping("/parse")
    public Map<String, Object> parseXML(@RequestParam String xml) {
        Map<String, Object> response = new HashMap<>();
        
        try {
            // VULNERABLE: SAXParserFactory with default configuration
            // Does not disable external entities
            SAXParserFactory factory = SAXParserFactory.newInstance();
            
            // These lines are commented out - they would make it secure!
            // factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            // factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            // factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            
            SAXParser saxParser = factory.newSAXParser();
            XMLHandler handler = new XMLHandler();
            
            // Parse the XML - XXE vulnerability occurs here
            saxParser.parse(new ByteArrayInputStream(xml.getBytes()), handler);
            
            response.put("status", "success");
            response.put("elements", handler.getElements());
            response.put("content", handler.getContent());
            
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", e.getMessage());
        }
        
        return response;
    }

    @GetMapping("/health")
    public Map<String, String> health() {
        Map<String, String> status = new HashMap<>();
        status.put("status", "healthy");
        status.put("parser", "SAX");
        return status;
    }

    /**
     * SAX Handler to process XML elements
     */
    static class XMLHandler extends DefaultHandler {
        private List<String> elements = new ArrayList<>();
        private StringBuilder content = new StringBuilder();
        private StringBuilder currentValue = new StringBuilder();

        @Override
        public void startElement(String uri, String localName, String qName, Attributes attributes) {
            elements.add(qName);
            currentValue.setLength(0);
        }

        @Override
        public void characters(char[] ch, int start, int length) {
            currentValue.append(ch, start, length);
        }

        @Override
        public void endElement(String uri, String localName, String qName) {
            String value = currentValue.toString().trim();
            if (!value.isEmpty()) {
                content.append(qName).append(": ").append(value).append("\n");
            }
        }

        public List<String> getElements() {
            return elements;
        }

        public String getContent() {
            return content.toString();
        }
    }
}