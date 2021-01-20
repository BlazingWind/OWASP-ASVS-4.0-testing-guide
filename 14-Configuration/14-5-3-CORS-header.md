# 14.5.3 CORS header

> Verify that the cross-domain resource sharing (CORS) Access-Control-Allow-Origin header uses a strict white-list of trusted domains to match against and does not support the "null" origin.

CWE 346

# Explanation

Cross-Origin Resource Sharing (CORS) is a mechanism that uses additional HTTP headers to tell browsers to give a web application running at one origin, access to selected resources from a different origin. A web application executes a cross-origin HTTP request when it requests a resource that has a different origin (domain, protocol, or port) from its own.

The Origin request header indicates where a fetch originates from. It is set automatically by the user agent to describe the security contexts that caused the user agent to initiate an HTTP request. It is sent with CORS requests, as well as with POST requests. It is similar to the Referer header, but, unlike this header, it doesn't disclose the whole path.

The origin header is always sent by the browser in a CORS request and indicates the origin of the request. To avoid using the wildcard or maintaining a white-list of websites, some implementations copy the Origin header from the request back in the response - the website ‘reflects’ it. Combined with Access-Control-Allow-Credentials: true, an attacker can trick a user visiting his website into doing Cross-Origin request and read the content of the response.

This control focuses on whitelisting of domains. A site requests a resource from another site, which will be called 'target' in this example. Target then checks if the requesting site is one of its whitelisted sites. If it is, the target sends a response with a header Access-Control-Allow-Origin: <requester>, and if not, the file is not loaded in the browser. Properly configured CORS is a good mechanism for preventing CSRF vulnerabilities.

A typical CORS request looks like this:

```
GET /resource HTTP/1.1
Host: target.com
Origin: https://hacker.com
Cookie: sessionid=...
```

And the response:

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://malicious-website.com
Access-Control-Allow-Credentials: true
...
```

# Testing methods

While we may not know what the whitelisted domains are, it doesn't matter for the sake of this control.

Access-Control-Allow-Origin can have values, *, <origin>, null. The * and null should not be used. If CORS is not configured or has a strict whitelist of trusted domains, and we will try to send a request with random value in the origin, the response will not contain Access-Control-Allow-Origin. null is a special value for the Origin header. The specification mentions it being triggered by redirects, and local HTML files. Some applications might whitelist the null origin to support local development of the application, but it is not a good practice.

## Proxy

1. Browse to the site in scope using the built-in browser. 
2. Enable script "14-5-3 CORS header.py" which can be found under Scripts > Active Rules. 
3. Go to Sites and select the site you wish to scan. Use a spider if you wish. Then right click the site (node) and choose Attack > Active Scan. Choose "Scripts only" policy (if you have not created a policy for active scan rules, follow the instruction under "Getting Started") and tick recurse. 
4. Click Start Scan.
5. The script sends a CORS request from an inexisitent domain to determine if the Access-Control-Allow-Origin header is configured with a wildcard, if it reflecting the Origin header or if the request was blocked.

## Netcat

We are going to send the request over netcat and based on the response we will see if CORS policy is misconfigured.

```jsx
echo -ne "HEAD / HTTP/1.1\r\nHost: example.com\r\nOrigin: randomvalue.test\r\n\r\n" | nc example.com 80
```

In the response you should see Access-Control-Allow-Origin header. If CORS is not configured or uses a strict whitelist, you will not see the header. Although the HTTP response was 200 and the resource would be fetched, it would not be loaded on a website.

If the randomvalue.test is reflected in the response in the “Access-Control-Allow-Origin” header, at this point it means that any domain can access resources from this domain. If the response contains any sensitive information it may be possible to retrieve them with a script from a website.

It may also happen that you recieve a response such as 301 or 302. Then you need to adjust the domain address accordingly.

## Curl

Unless you already know of specific resources on the website that are loaded using CORS, it is better to run the ZAP proxy script, but you may also use curl.

```jsx
curl -H "Origin: https://randomvalue.test" --verbose https://target.com
or
curl -I -X OPTIONS -H "Origin: exampletestsite.com" -H "Access-Control-Request-Method: GET" [https://www.webscantest.com/cors/cors.php](https://www.webscantest.com/cors/cors.php)
```

If there is a problem with certificate use option -k.

## Javascript (only tests null Origin)

Nick (njgibbon) has created a tiny CORS test on his github for testing CORS requests with null Origin, which can be accessed at

[https://github.com/njgibbon/nicks-cors-test.](https://github.com/njgibbon/nicks-cors-test.)

It consists of a Javascript file which makes a request to a target using AJAX without any origin specified. The author specifies that first you should change the dataType (in our case to html) and url to your target. Save it and load the files in the browser. Then in DevTools look at Console and see if there was raised an error. If there was, the app does not allow requests with null Origin. If there wasn't, the app DOES allow requests with null Origin and that means that the control is failed.

# Control

If you see a response with header Access-Control-Allow-Origin with directives that do not have a strict whitelist (uses f.ex. * or null), the control is failed.

If you see a response with header Access-Control-Allow-Origin with reflected Origin, and the value is always reflected even if the domain doesn't exist, the control is failed.

# Resources

[https://portswigger.net/web-security/cors](https://portswigger.net/web-security/cors)

[https://www.packetlabs.net/cross-origin-resource-sharing-cors/](https://www.packetlabs.net/cross-origin-resource-sharing-cors/)

[https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client_Side_Testing/07-Testing_Cross_Origin_Resource_Sharing.html](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client_Side_Testing/07-Testing_Cross_Origin_Resource_Sharing.html)

[https://www.sjoerdlangkemper.nl/2018/09/12/authorization-header-and-cors/](https://www.sjoerdlangkemper.nl/2018/09/12/authorization-header-and-cors/)

[http://demo.sjoerdlangkemper.nl/auth/fetch.html](http://demo.sjoerdlangkemper.nl/auth/fetch.html)