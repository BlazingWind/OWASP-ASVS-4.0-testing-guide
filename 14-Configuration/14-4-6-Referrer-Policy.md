# 14.4.6 Referrer-Policy

> Verify that a suitable "Referrer-Policy" header is included, such as "no-referrer"
or "same-origin".

CWE 116

# Explanation

HTTP requests may include Referrer header, which indicates origin or web page URL request was sent from. Referrer-Policy specifies how much information is sent in the Referer header. Sending full URL in Referer header may expose a lot of sensitive information.

Referrer-Policy has many directives, but the control focuses on two:

- no-referrer, which means that nop Referer header is sent, and
- same-origin, which only shows the origin of the URL, f.ex https://example.com/ even if the URL the request was made from was https://example.com/login or similar

Referrer-Policy should be used on sites that f.ex have a social media link in the footer or an image that is hosted on a third party but embedded in your page.

There are several ways Referrer-Policy can be implemented, such as:

- Via the Referrer-Policy HTTP header.
- Via a meta element with a name of referrer.
- Via a referrerpolicy content attribute on an a, area, img, iframe, or link element.
- Via the noreferrer link relation on an a, area, or link element.
- Implicitly, via inheritance.

*Taken from W3C Candidate Recommendation* [https://www.w3.org/TR/referrer-policy/#referrer-policy-delivery-meta](https://www.w3.org/TR/referrer-policy/#referrer-policy-delivery-meta)

It is also possible to implement it via Content-Security-Policy - see resources.

Although there are many ways to implement the policy, this control only tests against the header, since it it the most often used way of implementation.

# Testing methods

This control can be tested in DevTools, via a proxy or by viewing response returned by nmap script http-headers. A request can be also sent using curl or using any other banner grabbing tool. 

## Proxy

Enable script "14-4-6 Referrer-Policy.py" and browse to the site in scope. Preferably use a spider or and AJAX spider. The script will raise an alert if 'Referrer-Policy' header is not present. Additionally, the script tests if the Referrer-Policy header is configured with either of the directives: 'no-referrer' or 'same-origin'.

## Nmap

nmap -sV --script=http-headers <target.com>

# Control

If other directives than "no-referrer" or "same-origin" are specified, the control is failed.

# Resources

[https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)

[https://scotthelme.co.uk/csp-cheat-sheet/#referrer](https://scotthelme.co.uk/csp-cheat-sheet/#referrer)

Enable script "14-4-6 Referrer-Policy.py" and browse to the site in scope. Preferably use a spider or and AJAX spider. The script will raise an alert if 'Referrer-Policy' header is not present. Additionally, the script tests if the Referrer-Policy header is configured with either of the directives: 'no-referrer' or 'same-origin'.