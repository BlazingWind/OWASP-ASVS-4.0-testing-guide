# 14.4.3 Content Security Policy

> Verify that a content security policy (CSPv2) is in place that helps mitigate impact for XSS attacks like HTML, DOM, JSON, and JavaScript injection vulnerabilities.

CWE 1021

# Explanation

Content-Security-Policy is an HTTP header that helps detect, mitigate and report on many kinds of data injection attacks including XSS and clickjacking. CSP restricts how resources such as JavaScript, CSS and many more are loaded by the browser. CSP has many directives and how CSP looks like depends solely on what resources the site loads. A proper CSP policy will not be too long or too complex.

As an example - a site target.com might load a javascript analytics file from analytics.com, images from images.com and CSS from fonts.com. In this case a good CSP would look like this:

content-security-policy: default-src 'self'; img-src 'self' images.com; script-src 'self' analytics.com; style-src ‘self’ fonts.com; report-uri /some-report-uri;

Using report-uri or report-to directive is a good practice, since it instructs the browser to send reports of policy failures to the specified URI. The above CSP is very simple, but it was made only to show the principle behind it.

There also are versions of the header called X-Content-Security-Policy and X-Webkit-CSP, but they create unexpected behaviour and should be avoided.

# Testing methods

You may test it in a proxy or simply in Developer Tools of your favourite browser. Any request to the domain should receive in response the configured CSP.

It is hard to specify what a proper configuration looks like, but as a rule of a thumb it should not allow too many domains, shouldn't use wildcards ‘*’ and shouldn't use ‘unsafe-eval’ and ‘unsafe-inline’. If any scripts are loaded via inline script they should contain a nonce value or hash value.

## Proxy

Enable script "14-4-3 Content Security Policy.py" and browse to the site in scope. Preferably use a spider or and AJAX spider. The script will raise an alert if Content-Security-Policy header is not present or if the CSP is configured with the directives: 'unsafe-inline', 'unsafe-eval' and wildcards.

## Online CSP evaluator

You may also use an online CSP evaluator which will give you recommendation based on how the CSP looks like, such as:

[https://csp-evaluator.withgoogle.com/](https://csp-evaluator.withgoogle.com/)

# Control

If HTTP requests do not contain the header Content-Security-Policy, which is properly configured, the control is failed.

# Resources

[https://content-security-policy.com/](https://content-security-policy.com/)