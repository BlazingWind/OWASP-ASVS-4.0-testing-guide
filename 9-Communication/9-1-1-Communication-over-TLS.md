# 9.1.1 Communication over TLS

> Verify that secured TLS is used for all client connectivity, and does not fall back to insecure or unencrypted protocols.

CWE 319

# Explanation

Allowing a site to connect using unencrypted protocols is a major security risk and should not be allowed. Unencrypted protocols give an attacker a possibility to sniff the traffic and see all sensitive data being sent.

# Testing methods

## Bash script

I have written a small tool in bash that utilizes openssl for testing, which tests against the three L1 controls in Network Security category of ASVS. To execute the script, run:

`bash test.sh <domain to scan>`

 It prints out which controls are failed and which are successful.

## Curl

To test if website connects over HTTP run:

`curl -kis http://domain.com`

- `-k` allows to proceed with an insecure connection
- `-i` includes HTTP response headers in the output
- `-s` is silent mode

## Nmap

`nmap -sV --script ssl-enum-ciphers -p 443 <host>`

## Other tools

- sslyze
- testssl.sh

# Control

If communication over HTTP is allowed, the control is failed. If this requirement is failed, all L1 controls are failed in this section.

# Resources

[https://github.com/nabla-c0d3/sslyze](https://github.com/nabla-c0d3/sslyze)

[https://portswigger.net/bappstore/474b3c575a1a4584aa44dfefc70f269d](https://portswigger.net/bappstore/474b3c575a1a4584aa44dfefc70f269d)

[https://github.com/drwetter/testssl.sh](https://github.com/drwetter/testssl.sh)
