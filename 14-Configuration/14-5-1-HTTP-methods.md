# 14.5.1 HTTP methods

> Verify that the application server only accepts the HTTP methods in use by the application or API, including pre-flight OPTIONS.

CWE 749

# Explanation

OWASP testing guide has a very good explanation of the problem:

[https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods.md](https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods.md)

HTTP defines a set of request methods to indicate the desired action to be performed for a given resource.

`GET`

The GET method requests a representation of the specified resource. Requests using GET should only retrieve data.

`HEAD`

The HEAD method asks for a response identical to that of a GET request, but without the response body.

`POST`

The POST method is used to submit an entity to the specified resource, often causing a change in state or side effects on the server.

`PUT`

The PUT method is used to store the enclosed entity on a server - replaces all current representations of the target resource with the request payload.

`DELETE`

The DELETE method deletes the specified resource.

`CONNECT`

The CONNECT method establishes a tunnel to the server identified by the target resource.

`OPTIONS`

The OPTIONS method is used to describe the communication options for the target resource - to request available methods on a server - is employed to return the request that was received by the final recipient from the client so that it can diagnose the communication.

`TRACE`

The TRACE method performs a message loop-back test along the path to the target resource.

`PATCH`

The PATCH method is used to apply partial modifications to a resource.

There are also extended HTTP methods such as web-based distribution authoring and versioning(WEBDAV). WEBDAV can be used by clients to publish web contents and involves HTTP methods such as PROPFIND, MOVE, COPY, LOCK, UNLOCK, and MKCOL.

While GET and POST methods are used in most attacks, they themselves are not a problem and are required for a common plain server. PUT, DELETE, CONNECT and TRACE are not needed for functioning of a server and many have known exploits for them.

### Pre-flight OPTIONS

A CORS preflight request is a CORS request that checks to see if the CORS protocol is understood and a server can use specific methods and headers.

CORS allows one site to make a request to another.

A preflight request asks for the server’s permission to send the request - it isn’t the request itself. Instead, it contains metadata about it, such as which HTTP method is used and if the client added additional request headers. The server inspects this metadata to decide whether the browser is allowed to send the request.

For example, a client might be asking a server if it would allow a [DELETE](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/DELETE) request, before sending a DELETE request, by using a preflight request:

```
OPTIONS /resource/foo 
Access-Control-Request-Method: DELETE 
Access-Control-Request-Headers: origin, x-requested-with
Origin: [https://](https://foo.bar.org/)example.com
```

If the server allows it, then it will respond to the preflight request with an Access-Control-Allow-Methods response header, which lists DELETE:

```
HTTP/1.1 204 No Content
Connection: keep-alive
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Methods: POST, GET, OPTIONS, DELETE
Access-Control-Max-Age: 86400

```

One other set of Methods needs mentioning: ALL OTHERS. For some webservers, in order to enable/disable/restrict certain HTTP Methods, you explicitly set them one way or another in the configuration file. However, if no default is set, it can be possible to "inject" additional methods, bypassing certain access controls that the web server may have implemented (poorly). See for example [some more info on OWASP](https://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29#Arbitrary_HTTP_Methods).

# Testing methods

## Manually

You can test HTTP methods by sending single requests using telnet, openssl, netcat or other tools. You may also capture traffic using a proxy and then change the requests to match your needs. 

Using telnet:

`$ telnet <target> 80`

Then specify the method, the resource and HTTP version.

```jsx
GET / HTTP/1.1
Host: www.target.com
```

Then hit enter twice to send and to receive the messages. 

## Nmap

You can run an nmap script to find supported methods:

*nmap --script=http-methods.nse --script-args http-methods.retest=1 <IP>*

## Proxy

1. Browse to the site in scope using the built-in browser. 
2. Enable script "14-5-1 HTTP methods.py" which can be found under Scripts > Active Rules. 
3. Go to Sites and select the site you wish to scan. Use a spider if you wish. Then right click the site (node) and choose Attack > Active Scan. Choose "Scripts only" policy (if you have not created a policy for active scan rules, follow the instruction under "Getting Started") and tick recurse if you wish, but there is no requirement for it. 
4. Click Start Scan.
5. The script sends several HTTP methods to the target domain. If the answer is 2xx, the method may be allowed. Review the alerts.

# Control

Find all supported methods. If there are any others than GET, HEAD, POST and OPTIONS, the control is failed.

# Resources

[https://security.stackexchange.com/questions/21413/how-to-exploit-http-methods](https://security.stackexchange.com/questions/21413/how-to-exploit-http-methods)

[https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods)

[https://www.sans.org/reading-room/whitepapers/testing/penetration-testing-web-application-dangerous-http-methods-33945](https://www.sans.org/reading-room/whitepapers/testing/penetration-testing-web-application-dangerous-http-methods-33945)