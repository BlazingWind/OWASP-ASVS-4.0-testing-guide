# 14.5.2 Origin header

> Verify that the supplied Origin header is not used for authentication or access control decisions, as the Origin header can easily be changed by an attacker.

CWE 346

# Explanation

While it is not a common behavior, it may happen that a developer restricted access to some subpages or resources only to people that would use a specific Origin header in a request. It's a way  to enforce access control, though not a very good one, and should be avoided. As the control specifies, it is very easy to change the Origin header.

# Testing methods

There is no straight forward way to test it in a black box scenario. If during testing other controls you have encountered an error with a status code 403 forbidden, you may try to add an Origin header with the domain name you are testing or one of the domains belonging to 3rd party providers of the code that is loaded on the tested domain. Triggering 403 may also happen if you spider an application using OWASP ZAP or Burp Suite.

Let's say during testing you have sent a request as below:

```
GET /secret.txt HTTP/1.1
Host: target.com
```

And received a response:

```
HTTP/1.1 403 Forbidden
```

Then you can add an Origin header with the domain name (3rd party providers' domains) to the same request:

```
GET /secret.txt HTTP/1.1
Host: target.com
Origin: target.com
```

If it succeeds in fetching the resource, it means the Origin header was used for access control:

```
HTTP/1.1 200 OK
```

# Control

If the Origin header is used for any authentication or access control decisions, the control is failed.

# Resources

[https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny)