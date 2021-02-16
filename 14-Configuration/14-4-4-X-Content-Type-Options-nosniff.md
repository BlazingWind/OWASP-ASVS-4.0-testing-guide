# 14.4.4 X-Content-Type-Options: nosniff

> Verify that all responses contain X-Content-Type-Options: nosniff.

CWE 116

# Explanation

X-Content-Type-Options: nosniff is a protection against MIME sniffing vulnerabilities. MIME sniffing is a technique which determines an asset's file format, when no content type is provided. While MIME sniffing was created as a feature to detect when f.ex. a Javascript file was sent as Content-type: text/plain which would create a MIME type mismatch. Since the file is examined by the browser, it can cause Javascript to be rendered and opens a possibility for XSS attacks.

Developers might incorrectly set a value for Content-Type header for a response's content - for example a server may send Content-Type: text/plain for a Javascript resource. Browsers may render such resourcesm so the website operates as intended, even though it is a mismatch.

The header prevents that from happening.

# User Story and Scenario

Feature: HTTP response prevents browsers from overriding response content type
 	In order to prevent MIME-based attacks or MIME sniffing
 	As a Security Engineer
 	I want to ensure only the server-provided Content type is allowed


Scenario: Secure Content type responses from being modified by server
	Given an HTTP response
	And an HTTP Security header
	When determining Content type options
	Then nosniff is enforced

Examples:
| x-content-type-options: nosniff |

# Testing methods

This control can be tested in DevTools, via a proxy or by viewing response returned by nmap script http-headers. A request can be also sent using curl or using any other banner grabbing tool. 

## Proxy

Enable script "14-4-4 X-Content-Type-Options.py" and browse to the site in scope. Preferably use a spider or and AJAX spider. The script will raise an alert if  X-Content-Type-Options header is not present.

## Nmap

Nmap is a scanner which has built in scripts. One of them returns HTTP headers from a website, like X-Content-Type-Options headers:

nmap -sV --script=http-headers <target.com>

# Control

If HTTP requests do not contain the header X-Content-Type-Options: nosniff, the control is failed.

# Resources

[https://www.denimgroup.com/resources/blog/2019/05/mime-sniffing-in-browsers-and-the-security-implications/](https://www.denimgroup.com/resources/blog/2019/05/mime-sniffing-in-browsers-and-the-security-implications/)