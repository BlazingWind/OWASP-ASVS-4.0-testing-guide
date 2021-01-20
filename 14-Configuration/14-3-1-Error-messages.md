# 14.3.1 Error messages

> Verify that web or application server and framework error messages are configured to deliver user actionable, customized responses to eliminate any unintended security disclosures.

CWE 209

# Explanation

Default error pages usually disclose information about the underlying software and web server in use. Optimally instead of default error pages, there should be a custom, user-actionable error pages returned. 

# Testing methods

There is no one full proof way to test that all errors are user actionable and contain no security disclosures - most often they come up after a longer reconnaissance process of a web application during a web app pentest or a scan. There are though several tests that may help triggering several types of errors, e.g. by changing HTTP methods, headers and body of the message to trigger one of the status codes. Some are presented in the OWASP WSTG chapter 8.1.

There are many tools which can be used for testing: telnet, curl, a proxy and many other. It is best to trigger errors that would give you one of the 4xx and 5xx http code responses. 

Examine the response and see if there are any information about the services running or the server version.

## Proxy

1. Browse to the site in scope using the built-in browser. 
2. Enable script "14-3-1 Error messages.py" which can be found under Scripts > Active Rules. 
3. Go to Sites and select the site you wish to scan. Use a spider if you wish. Then right click the site (node) and choose Attack > Active Scan. Choose "Scripts only" policy (if you have not created a policy for active scan rules, follow the instruction under "Getting Started") and tick recurse if you wish to execute the script on each subnode - in this case there is no need to tick it off, but if you wish to have more coverage you may tick it off. Caution: this will produce much more traffic, which in turn will generate errors and will give you many more alerts.
4. Click Start Scan.
5. The script attempts to trigger errors in a web application and checks the response for any software component disclosure - if it finds one, it raises an alert. Most of the attacks are based on OWASP WSTG v4.1 chapter 8.1 Testing for Error Code.
6. Click  the "Reponse" tab and go through each response - it may happen that the script didn't detect a security disclosure. If this is the case feel free to report it on this project's Github.

# Control

If errors do not disclose any information about the server and its services, the control is successful.

# Resources

[https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)

[https://owasp.org/www-project-proactive-controls/v3/en/c10-errors-exceptions](https://owasp.org/www-project-proactive-controls/v3/en/c10-errors-exceptions)

[https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server.html](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server.html)

[https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code.html](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code.html)