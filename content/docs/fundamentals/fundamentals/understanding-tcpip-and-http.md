---
title: "Understanding TCP/IP and HTTP(S): A Deep Dive with Wireshark"
description: "This tutorial explores the fundamentals of TCP/IP and HTTP(S) protocols, using Wireshark for hands-on packet analysis."
image: "https://armur-ai.github.io/armur-blog-pentest/images/security-fundamentals.png"
icon: "code"
draft: false
---

## Introduction

This tutorial dives deep into the core protocols that power the internet: TCP/IP and HTTP(S). We will explore their functionalities, how they interact, and how to analyze network traffic using the powerful packet analyzer, Wireshark. Understanding these concepts is crucial for anyone interested in network security, web development, or simply gaining a deeper understanding of how the internet works.

### What is TCP/IP?

TCP/IP stands for Transmission Control Protocol/Internet Protocol. It's a suite of networking protocols that define how data is transmitted across the internet. TCP/IP operates at different layers, each responsible for specific tasks:

* **Application Layer:** Handles user-facing applications like web browsers, email clients, etc. This layer uses protocols like HTTP, FTP, SMTP.
* **Transport Layer:** Provides reliable and ordered data delivery between applications. TCP and UDP are the main protocols at this layer.
* **Network Layer:** Responsible for routing data packets between networks. IP is the core protocol at this layer.
* **Link Layer:** Handles the physical transmission of data over the network medium (e.g., Ethernet, Wi-Fi).

### What is HTTP(S)?

HTTP (Hypertext Transfer Protocol) is the foundation of the World Wide Web. It defines how web browsers communicate with web servers to request and receive web pages and other resources. HTTPS (HTTP Secure) is a secure version of HTTP that encrypts communication between the browser and the server using SSL/TLS, ensuring data confidentiality and integrity.

### What is Wireshark?

Wireshark is a free and open-source network protocol analyzer. It allows you to capture and inspect network traffic in real-time, providing detailed information about each packet. Wireshark is an invaluable tool for network troubleshooting, security analysis, and understanding network protocols.

## Understanding TCP/IP with Wireshark

Let's explore TCP/IP concepts with practical examples using Wireshark.

**Step 1: Install Wireshark**

Download and install Wireshark from the official website: [Wireshark Download](https://www.wireshark.org/download.html)

**Step 2: Capture Network Traffic**

1. Open Wireshark.
2. Select the network interface you want to capture traffic from (e.g., Wi-Fi, Ethernet).
3. Click the "Start" button (shark fin icon) to begin capturing.
4. Open a web browser and visit a website.
5. Stop the capture in Wireshark.

**Step 3: Analyze TCP/IP Packets**

Wireshark displays the captured packets in a list. Each packet contains detailed information about the communication.

* **Source and Destination IP Addresses:** Identify the IP addresses of the communicating devices.
* **Source and Destination Ports:** Indicate the application or service used (e.g., port 80 for HTTP, port 443 for HTTPS).
* **Protocol:** Shows the protocol used (e.g., TCP, UDP, HTTP).
* **Data:** Contains the actual data being transmitted.

**Example: Analyzing an HTTP Request**

1. Find an HTTP packet in the capture (look for packets with "HTTP" in the "Protocol" column).
2. Right-click the packet and select "Follow" -> "TCP Stream".
3. Wireshark will display the entire conversation between the browser and the server.
4. You can see the HTTP request sent by the browser and the HTTP response sent by the server.

**Key TCP/IP Concepts Illustrated:**

* **Three-Way Handshake:** Observe the TCP SYN, SYN-ACK, and ACK packets that establish the connection.
* **Data Segmentation:** Notice how large data is divided into smaller segments for transmission.
* **Acknowledgement and Retransmission:** See how TCP ensures reliable data delivery by acknowledging received segments and retransmitting lost ones.

## Understanding HTTP(S) with Wireshark

Now, let's focus on HTTP(S) traffic.

**Step 1: Capture HTTPS Traffic**

Repeat the steps for capturing network traffic, but this time visit a website using HTTPS (e.g., https://www.google.com).

**Step 2: Analyze HTTPS Packets**

You'll notice that the "Data" column for HTTPS packets is encrypted. This is because HTTPS uses SSL/TLS to secure communication.

**Step 3: Decrypting HTTPS Traffic**

To decrypt HTTPS traffic, you need to provide Wireshark with the SSL/TLS private key used by the server. This is usually not feasible unless you have access to the server's configuration.

**Alternative: Analyzing HTTPS Handshake**

Even without decrypting the data, you can still gain valuable insights from the HTTPS handshake.

1. Find the TLS handshake packets (look for packets with "TLSv1.2" or "TLSv1.3" in the "Protocol" column).
2. Expand the "TLS" section in the packet details pane.
3. You can see information about the cipher suite used, the server's certificate, and other security parameters.

## Best Practices for Network Analysis with Wireshark

* **Filter Traffic:** Use display filters to focus on specific protocols or conversations.
* **Follow Streams:** Analyze the entire conversation between two devices.
* **Inspect Packet Details:** Examine the different fields within each packet for insights.
* **Use Expert Info:** Wireshark provides expert analysis and highlights potential issues.
* **Stay Updated:** Regularly update Wireshark to benefit from new features and security updates.

## Conclusion

This tutorial provided a comprehensive overview of TCP/IP and HTTP(S) protocols, along with practical examples using Wireshark. Understanding these concepts and using Wireshark effectively is essential for anyone involved in network security or administration. Continue exploring Wireshark's features and apply your knowledge to analyze real-world network traffic and enhance your understanding of network communications. 