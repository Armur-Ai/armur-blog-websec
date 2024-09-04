---
title: "Website & DNS Enumeration: Uncovering Subdomains and Mirroring Websites with dig, nslookup, Sublist3r, and More"
description: "TLearn about DNS enumeration techniques using dig, nslookup, and Fierce, subdomain discovery with Sublist3r and Amass, and website mirroring with HTTrack and Wget."
image: "https://armur-ai.github.io/armur-blog-pentest/images/security-fundamentals.png"
icon: "code"
draft: false
---

## Introduction

This tutorial covers essential techniques for website and DNS enumeration, including DNS enumeration with dig, nslookup, and Fierce, subdomain discovery with Sublist3r and Amass, and website mirroring with HTTrack and Wget. These techniques are crucial for security assessments, reconnaissance, and understanding the scope of a target web application.

### DNS Enumeration

DNS (Domain Name System) is a hierarchical database that translates domain names (e.g., google.com) into IP addresses. DNS enumeration involves querying DNS servers to gather information about a target domain, such as:

* **Hostnames:** Identifying individual servers within a domain.
* **Mail servers:** Discovering email servers associated with the domain.
* **Name servers:** Identifying the authoritative DNS servers for the domain.

### dig and nslookup

`dig` (Domain Information Groper) and `nslookup` are command-line tools for querying DNS servers.

**Example: Using dig**

```bash
dig example.com ANY
```

This command queries the DNS server for all available information about "example.com".

**Example: Using nslookup**

```bash
nslookup example.com
```

This command provides basic information about the domain, including its IP address.

### Fierce

Fierce is a more advanced DNS enumeration tool designed for security auditing. It performs zone transfers and brute-force attacks to discover subdomains.

**Example: Using Fierce**

```bash
fierce -dns example.com
```

This command attempts to perform a zone transfer and brute-force subdomain discovery for "example.com".

### Subdomain Enumeration

Subdomains are subdivisions of a domain (e.g., blog.example.com, mail.example.com). Subdomain enumeration involves discovering all subdomains associated with a target domain.

### Sublist3r

Sublist3r is a Python tool that enumerates subdomains using various search engines and online databases.

**Step 1: Install Sublist3r**

```bash
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
pip install -r requirements.txt
```

**Step 2: Enumerate Subdomains**

```bash
python3 sublist3r.py -d example.com
```

This command enumerates subdomains for "example.com" using various sources.

### Amass

Amass is another powerful subdomain enumeration tool that utilizes multiple techniques, including brute-forcing, DNS scraping, and certificate transparency logs.

**Step 1: Install Amass**

Download and install Amass from the official website: [Amass Download](https://github.com/OWASP/Amass/releases)

**Step 2: Enumerate Subdomains**

```bash
amass enum -d example.com
```

This command enumerates subdomains for "example.com" using various techniques.

### Knock

Knockpy is a Python tool specifically designed for subdomain brute-forcing. It uses wordlists to generate potential subdomain names and checks if they resolve.

**Step 1: Install Knockpy**

```bash
pip install knockpy
```

**Step 2: Brute-force Subdomains**

```bash
knockpy example.com
```

This command brute-forces subdomains for "example.com" using a default wordlist.

### Website Mirroring and Crawling

Website mirroring involves creating a local copy of a website. Crawling involves traversing a website's structure and downloading its content.

### HTTrack

HTTrack is a free and open-source website copier. It allows you to download a website's content, including HTML files, images, and other resources.

**Step 1: Install HTTrack**

Download and install HTTrack from the official website: [HTTrack Download](https://www.httrack.com/)

**Step 2: Mirror a Website**

1. Open HTTrack.
2. Create a new project.
3. Enter the website URL you want to mirror.
4. Configure the mirroring options (e.g., depth, filters).
5. Start the mirroring process.

### Wget

`wget` is a command-line utility for downloading files from the web. It can be used to mirror websites by recursively downloading all linked resources.

**Example: Mirroring with Wget**

```bash
wget -mkp -np -E -r -l 1 https://www.example.com/
```

This command recursively mirrors the website "example.com" up to a depth of 1, preserving directory structure and converting links to local paths.

## Best Practices for Website and DNS Enumeration

* **Respect robots.txt:** Avoid accessing resources that are disallowed by the website's robots.txt file.
* **Limit Requests:** Be mindful of the number of requests you send to a server to avoid overloading it.
* **Use Multiple Tools:** Combine different tools to get a comprehensive view of the target.
* **Verify Results:** Manually verify discovered subdomains and information to ensure accuracy.
* **Stay Ethical:** Only conduct enumeration activities within legal and ethical boundaries.

## Conclusion

This tutorial provided an overview of techniques and tools for website and DNS enumeration, including DNS enumeration with dig, nslookup, and Fierce, subdomain discovery with Sublist3r and Amass, and website mirroring with HTTrack and Wget. These techniques are essential for security professionals, penetration testers, and researchers to gather information about target websites and understand their structure. Remember to practice responsible disclosure and respect website owners' policies while conducting enumeration activities.