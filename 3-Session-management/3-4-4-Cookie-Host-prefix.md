# 3.4.4 Cookie Host prefix

> Verify that cookie-based session tokens use "__Host-" prefix (see references) to provide session cookie confidentiality.

CWE 16

# Explanation

__Host prefix can be set only on cookies with Secure flag, that use encrypted HTTPS, have no domain specified (cannot be set to subdomains) and have the Path set to "/".

# Testing methods

### Cookies

Log in to the application and go to Application tab > Cookies > choose the name of the target domain. Find the cookies used as session tokens and see if they have the __Host prefix

## ZAP

Similar to ChromeDevTools, you can look at the traffic in ZAP or other proxy. After logging in in a built in or preconfigured browser, you will see the request for login sent in the History tab. In following requests and responses you will find cookies.  

# Control

If the cookie-based session tokens do not have __Host prefix set, the control is failed.

# Resources

[https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

[https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies)

[https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Directives](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Directives)