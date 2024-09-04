---
title: "Injection Attacks: Understanding and Exploiting XSS and SQLi with Burp Suite and sqlmap"
description: "This tutorial explores injection attacks, focusing on Cross-Site Scripting (XSS) and SQL Injection (SQLi), and demonstrates exploitation techniques using Burp Suite and sqlmap."
image: "https://armur-ai.github.io/armur-blog-pentest/images/security-fundamentals.png"
icon: "code"
draft: false
---

## Introduction

Injection attacks are a prevalent class of web application vulnerabilities that occur when untrusted data is sent to an interpreter as part of a command or query. This tutorial focuses on two common types of injection attacks: Cross-Site Scripting (XSS) and SQL Injection (SQLi). We'll explore their mechanics, impact, and exploitation techniques using tools like Burp Suite and sqlmap.

### Cross-Site Scripting (XSS)

XSS vulnerabilities arise when user-supplied input is not properly sanitized and is reflected back to the browser. This allows attackers to inject malicious scripts into web pages viewed by other users.

**Types of XSS:**

* **Reflected XSS:** Malicious script is reflected back to the user's browser immediately after being submitted.
* **Stored XSS:** Malicious script is stored on the server and executed for every user who views the affected page.
* **DOM-based XSS:** Malicious script is executed by manipulating the Document Object Model (DOM) in the user's browser.

**Impact of XSS:**

* **Session Hijacking:** Stealing user sessions and gaining unauthorized access.
* **Data Theft:** Accessing sensitive information like cookies, passwords, and personal data.
* **Website Defacement:** Modifying the appearance or content of a website.
* **Malware Distribution:** Redirecting users to malicious websites or downloading malware.

**Exploiting XSS with Burp Suite:**

Burp Suite is a powerful web application security testing tool that can be used to identify and exploit XSS vulnerabilities.

**Step 1: Intercepting Requests**

Configure Burp Suite as your browser's proxy and intercept HTTP requests.

**Step 2: Injecting XSS Payloads**

Modify the intercepted request to inject an XSS payload into a vulnerable parameter.

**Example XSS Payload:**

```html
<script>alert('XSS')</script>
```

**Step 3: Analyzing the Response**

Forward the modified request and observe the response in your browser. If the payload is executed, you'll see an alert box.

### SQL Injection (SQLi)

SQLi vulnerabilities occur when user-supplied input is included in SQL queries without proper sanitization. This allows attackers to manipulate the query and potentially access or modify sensitive data.

**Types of SQLi:**

* **Error-based SQLi:** Exploits database error messages to reveal information.
* **Union-based SQLi:** Uses the UNION operator to combine legitimate and malicious queries.
* **Blind SQLi:** Infers information based on the application's response to true or false conditions.

**Impact of SQLi:**

* **Data Leakage:** Accessing sensitive data like usernames, passwords, and credit card information.
* **Database Manipulation:** Modifying or deleting data in the database.
* **Authentication Bypass:** Gaining unauthorized access to the application.
* **Server Compromise:** Taking control of the database server.

**Exploiting SQLi with sqlmap:**

sqlmap is an automated SQL injection tool that can identify and exploit SQLi vulnerabilities.

**Step 1: Identify Vulnerable Parameters**

Use Burp Suite or other tools to identify potential SQLi vulnerable parameters in web requests.

**Step 2: Run sqlmap**

```bash
sqlmap -u "http://example.com/vulnerable_page?id=1" --dbs
```

This command instructs sqlmap to test the "id" parameter for SQLi vulnerabilities and attempt to enumerate the databases.

**Step 3: Explore Data**

sqlmap offers various options to enumerate tables, columns, and data within the database.

**Example: Dumping Data**

```bash
sqlmap -u "http://example.com/vulnerable_page?id=1" -D database_name -T table_name --dump
```

This command dumps data from the specified table.

## Best Practices for Preventing Injection Attacks

* **Input Sanitization:** Properly sanitize all user-supplied input before using it in queries or commands.
* **Parameterized Queries:** Use parameterized queries or prepared statements to prevent SQL injection.
* **Output Encoding:** Encode output to prevent XSS vulnerabilities.
* **Context-Aware Escaping:** Escape user input based on the context where it is used.
* **Security Testing:** Regularly conduct security testing to identify and address vulnerabilities.

## Conclusion

This tutorial covered injection attacks, focusing on XSS and SQLi vulnerabilities. We explored their mechanics, impact, and exploitation techniques using Burp Suite and sqlmap. Understanding these vulnerabilities and implementing proper security measures is crucial for protecting web applications from injection attacks.