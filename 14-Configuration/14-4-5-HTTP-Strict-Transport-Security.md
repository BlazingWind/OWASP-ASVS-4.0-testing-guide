# 14.4.5 HTTP Strict Transport Security

> Verify that HTTP Strict Transport Security headers are included on all responses and for all subdomains, such as Strict-Transport-Security: max-age=15724800; includeSubdomains.

CWE 523

# Explanation

HTTP Strict-Transport-Security HSTS header is used to tell a browser that a website should only be accessed using HTTPS. It has two directives, which should both be included in a configuration:

- max-age=<expire-time>, tells the browser to enable HSTS fo a domain and remember it for a given number of seconds. Best practices specify `max-age=31536000` which is a year.
- includeSubDomains - HSTS covers all subdomains of a domain.

There is one more directive, preload, but it is not required to use.

# Testing methods

This control can be tested in DevTools, via a proxy or by viewing response returned by nmap script http-headers. A request can be also sent using curl or using any other banner grabbing tool. 

## Proxy

Enable script "14-4-5 HTTP Strict Transport Security.py" and browse to the site in scope. Preferably use a spider or and AJAX spider. The script will raise an alert if 'Strict-Transport-Security' header is not present. Additionally, the script test if the HSTS header is configured with the directives: max-age=15724800; includeSubdomains. Max age should be at least 15724800, but a longer time is preferred.

## Nmap

nmap -sV --script=http-headers <target.com>

# Control

If HTTP requests do not contain the header Strict-Transport-Security: max-age=31536000; includeSubDomains; the control is failed.

# Resources

[https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)