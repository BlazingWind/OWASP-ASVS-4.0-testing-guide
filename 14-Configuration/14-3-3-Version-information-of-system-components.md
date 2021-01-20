# 14.3.3 Version information of system components

> Verify that the HTTP headers or any part of the HTTP response do not expose detailed version information of system components.

CWE 200

# Explanation

Giving away too much information in HTTP responses allows attackers to make more targeted attacks. Information may be exposed in Server header or based on the ordering of the header fields. Some software adds also it's own headers, which may expose what is running on the server.

# Testing methods

This control can be tested in DevTools, via a proxy or by viewing response returned by nmap script http-headers. A request can be also sent using curl or openssl or using any other banner grabbing tool. 

## Proxy

Enable script "14-3-3 Version information of system components.py" and browse to the site in scope. Preferably use a spider or and AJAX spider. The script will raise an alert if 'Server' or X-Powered-By' header is present. It may happen that detailed information about the system component is obscured - review the findings of the script before assessing the control. 

## Nmap

Nmap is a scanner which has built in scripts. One of them returns HTTP headers from a website, like Server and X-Powered-By headers:

nmap -sV --script=http-headers <target.com>

# Control

Observe if the Server header with server version is in the response or if it is possible to tell what the server version is from other headers. If yes, control is failed.

# Resources

[https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server.html](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server.html)

Disabling server header in IIS [https://support.qlik.com/articles/000063710](https://support.qlik.com/articles/000063710)