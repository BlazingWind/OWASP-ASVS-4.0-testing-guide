# 5.1.1 HTTP parameter pollution

> Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (GET, POST, cookies, headers, or environment variables).

CWE 235

# Explanation

HTTP parameter pollution tests how the applications responds to multiple parameters with the same name. Since there is no RFC standard specifying how a web server should respond to multiple parameters, and every web server technology can define the default behavior. Some applications ignore the second instance of a parameter in a URL, some ignore the first, some concatenate them. Any of those behaviors can cause severe vulnerabilities.

Proper input encoding and input validation is sufficient to prevent HPP vulnerabilities. For many web applications, to prevent HPP the query string delimiter (&, ;) and its encoded versions should be filtered in GET, POST, cookies, headers, or environment variables as a minimum. As a general rule: if existing input validation and other security mechanisms are sufficient on single inputs, and if the server assigns only the first or last polluted parameters, then parameter pollution does not reveal a vulnerability. If the duplicate parameters are concatenated, different web application components use different occurrences or testing generates an error, there is an increased likelihood of being able to use parameter pollution to trigger security vulnerabilities.

# Testing methods

## ZAP helper script

Enable script "5-1-1 HTTP parameter pollution" and browse to the site in scope. Preferably use a spider or and AJAX spider.  The script looks for any parameters in URLs and in POST form fields and raises an alert on all parameters it has found. Most of the parameters found will be innocuous, but it is important to find among them any that may be used in a malicious way - such as a parameter that symbolize a session token ('session', 'jwt', 'id', 'auth'), ones that symbolize access ('access', 'verify', 'retries') or ones that may mean execution of a command or code ('cmd', 'file', 'action').  There may be many more parameters which depends on the tested application. 

While it is possible to run an automated test which would try to supply a parameter twice, it is not possible to detect whether application's response poses a security risk, especially when testing server-side HTTP parameter pollution. Testing for HPP should be done manually. The test would require inputting parameters in GET, POST, cookies, headers and environment variables.

## ZAP active scan rule

ZAP has an active scan rule which can help find some of the HPP client-side vulnerabilities, called 'HTTP parameter pollution', which is currently in Beta. To install and activate it, you first need to go to Marketplace > find Beta Active Rules > install. Then go to Active Scan Policy > choose a Policy > Injection > set Threshold for HTTP parameter pollution to Medium. Then scan an application using 'recurse' just like with any other active scan.

# Control

Review the helper script findings and find out how the application reacts to if any of the parameters poses a security risk. 

# Resources

[https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution.html](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution.html)

[https://owasp.org/www-pdf-archive/AppsecEU09_CarettoniDiPaola_v0.8.pdf](https://owasp.org/www-pdf-archive/AppsecEU09_CarettoniDiPaola_v0.8.pdf)

[http://www.madlab.it/slides/BHEU2011/whitepaper-bhEU2011.pdf](http://www.madlab.it/slides/BHEU2011/whitepaper-bhEU2011.pdf)

[https://shahjerry33.medium.com/http-parameter-pollution-its-contaminated-85edc0805654](https://shahjerry33.medium.com/http-parameter-pollution-its-contaminated-85edc0805654)

[https://andresriancho.com/recaptcha-bypass-via-http-parameter-pollution/](https://andresriancho.com/recaptcha-bypass-via-http-parameter-pollution/)

[https://www.ikkisoft.com/stuff/HPParticle.pdf](https://www.ikkisoft.com/stuff/HPParticle.pdf)
