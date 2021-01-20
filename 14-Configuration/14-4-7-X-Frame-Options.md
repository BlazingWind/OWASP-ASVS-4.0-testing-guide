# 14.4.7 X-Frame-Options or CSP: frame-ancestors

> Verify that a suitable X-Frame-Options or Content-Security-Policy: frame-ancestors header is in use for sites where content should not be embedded in a third-party site.

CWE 346

# Explanation

X-Frame-Options header tells your browser how to behave when handling your site's content. It protects against clickjacking by not allowing rendering of a page in a frame. This can include rendering of a page in a`<frame>`,`<iframe>`, or `<object>`.

Iframes are used to embed and isolate third party content into a website. Examples of things that use iframes might include social media sharing buttons, Google Maps, video players, audio players, third party advertising, and even some OAuth implementations.

X-Frame-Options has three directives: deny, sameorigin and allow-from *uri*.

- The deny directive completely disables the loading of the page in a frame, regardless of what site is trying.
- The sameorigin directive allows the page to be loaded in a frame on the same origin (domain, http/https scheme and port) as the page itself. It is up to a browser vendor whether this applies to all of the frame's ancestors.
- The allow-from *uri* directive allows the page to be loaded in an iframe on the specified domain or origin, but it is obsolete. There are browsers that do not support this directive and if a user uses one of those browsers, they will not be protected with X-Frame-Options from clickjacking.

Using Content-Security-Policy: frame-ancestors is very similar to X-Frame-Options and this control specifies that either of them can be used, as long as it is properly configured.

CSP: frame ancestors directive can be set to several values:

- ‘none’ which is the same as X-Frame-Options: deny
- 'self' which refers to the origin from which the protected document is being served, including the same URL scheme and port number.
- <source> which can be defined in several ways. It's fairly simple to configure but in case of doubts visit

# Testing methods

This control can be tested in DevTools, via a proxy or by viewing response returned by nmap script http-headers. A request can be also sent using curl or using any other banner grabbing tool. 

## Proxy

Enable script "14-4-7 X-Frame-Options or CSP frame-ancestors.py" and browse to the site in scope. Preferably use a spider or and AJAX spider. The script will raise an alert if 'X-Frame-Options' or Content-Security-Policy header with directive frame-ancestors is not present. Additionally, the script tests if the CSP header uses a wildcard, which renders the header useless.

## Nmap

nmap -sV --script=http-headers <target.com>

# Control

If any of:

- X-Frame-Options: deny or
- X-Frame-Options: sameorigin or
- Content-Security-Policy: frame-ancestors ‘none’
- Content-Security-Policy: frame-ancestors <source>

is present in server response, the control is successful.

# Resources

[https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors)

[https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)