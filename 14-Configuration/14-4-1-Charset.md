# 14.4.1 Charset

> Verify that every HTTP response contains a Content-Type header. text/*, /+xml and application/xml content types should also specify a safe character set (e.g., UTF-8, ISO-8859-1).

CWE 173

# Explanation

The header Content-Type denotes what the content is encoded in. By declaring Content-Type in a response it is possible to hinder XSS attacks leveraging different encodings than the server expects.

Not setting a charset in the Content-Type header can cause the browser to attempt to sniff the charset. An attacker can send a payload by encoding special characters in f. ex. UTF-7 and bypass application's defensive measures. This is not an issue in modern browsers support, since UTF-7 is not supported anymore, but nevertheless it is a best practice not to allow the browser to sniff the charset by setting it in Content-Type header. 

# Testing methods

This control can be tested via a proxy. Observing the traffic in DevTools or sending single requests using curl or other banner grabbing tools is not recommended, since all resources should use a 'Content-Type' header and additionally the types specified above should contain a charset.

## Proxy

Enable script "14-4-1 Charset.py" and browse to the site in scope. Preferably use a spider or and AJAX spider. The script will raise an alert if 'Content-Type' header is present and if the header specifies a safe charset for text/*, */*+xml and application/xml content types.

# Control

If there is an HTTP response not containing Content-Type header or Content-Type header with types text/*, /+xml and application/xml do not have a declared charset, the control is failed.

# Resources

[https://portswigger.net/kb/issues/00800200_html-does-not-specify-charset](https://portswigger.net/kb/issues/00800200_html-does-not-specify-charset)

[https://en.wikipedia.org/wiki/Content_sniffing](https://en.wikipedia.org/wiki/Content_sniffing)

[https://www.leviathansecurity.com/white-papers/flirting-with-mime-types](https://www.leviathansecurity.com/white-papers/flirting-with-mime-types)

[https://www.w3.org/International/questions/qa-html-encoding-declarations](https://www.w3.org/International/questions/qa-html-encoding-declarations)

[https://www.w3.org/Protocols/rfc1341/4_Content-Type.html](https://www.w3.org/Protocols/rfc1341/4_Content-Type.html)

[https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types)

[https://www.w3.org/International/questions/qa-css-charset](https://www.w3.org/International/questions/qa-css-charset)

[https://github.com/OWASP/ASVS/issues/710](https://github.com/OWASP/ASVS/issues/710)