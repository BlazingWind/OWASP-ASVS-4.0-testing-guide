# 9.1.3 TLS versions

> Verify that old versions of SSL and TLS protocols, algorithms, ciphers, and configuration are disabled, such as SSLv2, SSLv3, or TLS 1.0 and TLS 1.1. The latest version of TLS should be the preferred cipher suite.

# Explanation

As of January 2020 Google Chrome marks sites using TLS1.0 and TLS1.1 certificates for encryption as insecure and in 2021 will not load websites that try to connect over TLS1.0 or TLS1.1. All protocol versions below TLS1.2 have known vulnerabilities or are otherwise insecure. Therefore, a website has to use only secure protocols, such as TLS1.2 and TLS1.3.

# Testing methods

## Bash script

I have written a small tool in bash that utilizes openssl for testing, which tests against the three L1 controls in Network Security category of ASVS. To execute the script, run:

`bash [test.sh](http://test.sh) <domain to scan>`

 It prints out which controls are failed and which are successful.

## Curl

To test if which TLS versions does the server support run:

`curl -2 -is https://example.com`

- `-2` uses SSL version 2 for connection
- Test other TLS versions by replacing `-2` option with other options: `-3` (for SSLv3), `--tlsv1.0`, `--tlsv.1.1`, `--tlsv1.2`, and `--tlsv1.3`

The response for attempt to connect over  SSLv2, SSLv3, TLSv1.0 and TLSv1.1 should not be allowed to connect and should be instead redirected to HTTPS over TLSv1.2 or TLSv1.3 with HTTP/1.1 301 Moved Permanently or similar status code.

## Nmap

`nmap -sV --script ssl-enum-ciphers -p 443 <host>`

## Other tools

- sslyze
- testssl.sh

# Control

If communication is allowed using TLS versions lower than TLSv1.2 the control is failed.

# Resources

[https://github.com/nabla-c0d3/sslyze](https://github.com/nabla-c0d3/sslyze)

[https://portswigger.net/bappstore/474b3c575a1a4584aa44dfefc70f269d](https://portswigger.net/bappstore/474b3c575a1a4584aa44dfefc70f269d)

[https://github.com/drwetter/testssl.sh](https://github.com/drwetter/testssl.sh)