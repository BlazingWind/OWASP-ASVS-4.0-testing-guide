# 9.1.2 Strong algorithms

> Verify using online or up to date TLS testing tools that only strong algorithms, ciphers, and protocols are enabled, with the strongest algorithms and ciphers set as preferred.

# Explanation

SSLabs has written a TLS deployment best practice document which comes with a list of recommended ciphersuites. 

[https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)

Here is the list from the document:

```
ECDHE-ECDSA-AES128-GCM-SHA256
ECDHE-ECDSA-AES256-GCM-SHA384
ECDHE-ECDSA-AES128-SHA
ECDHE-ECDSA-AES256-SHA
ECDHE-ECDSA-AES128-SHA256
ECDHE-ECDSA-AES256-SHA384
ECDHE-RSA-AES128-GCM-SHA256
ECDHE-RSA-AES256-GCM-SHA384
ECDHE-RSA-AES128-SHA
ECDHE-RSA-AES256-SHA
ECDHE-RSA-AES128-SHA256
ECDHE-RSA-AES256-SHA384
DHE-RSA-AES128-GCM-SHA256
DHE-RSA-AES256-GCM-SHA384
DHE-RSA-AES128-SHA
DHE-RSA-AES256-SHA
DHE-RSA-AES128-SHA256
DHE-RSA-AES256-SHA256
```

As a rule of thumb only ciphersuites that utilize ECDHE and DHE are recommended, which provide forward secrecy.

# Testing methods

## Bash script

I have written a small tool in bash that utilizes openssl for testing, which tests against the three L1 controls in Network Security category of ASVS. To execute the script, run:

`bash [test.sh](http://test.sh) <domain to scan>`

It prints out which controls are failed and which are successful. The script compares the connected ciphersuites to the ones recommended by SSLabs in their best practices document.

## Nmap

`nmap -sV --script ssl-enum-ciphers -p 443 <host>`

## Other tools

- sslyze
- testssl.sh

# Control

If the supported ciphersuites are different the recommended ones, the control is failed.

# Resources

[https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)

[https://github.com/nabla-c0d3/sslyze](https://github.com/nabla-c0d3/sslyze)

[https://portswigger.net/bappstore/474b3c575a1a4584aa44dfefc70f269d](https://portswigger.net/bappstore/474b3c575a1a4584aa44dfefc70f269d)

[https://github.com/drwetter/testssl.sh](https://github.com/drwetter/testssl.sh)