# 3.4.1 Cookie Secure attribute

> Verify that cookie-based session tokens have the 'Secure' attribute set.

CWE 614

Proactive Control C6

# Explanation

Setting Secure attribute on a session cookie instructs a browser to send the cookie only over an encrypted HTTPS connection. Even if a site is configured to use only HTTPS, the web browser can be tricked to disclose the cookie over an unencrypted protocol. Sites using HTTP can't set cookies with this attribute.

# Testing methods

### Cookies

Log in to the application and go to Application tab > Cookies > choose the name of the target domain. Find the cookies used as session tokens and check if they have the Secure attribute set.

## ZAP

Similar to ChromeDevTools, you can look at the traffic in ZAP or other proxy. After logging in in a built in or preconfigured browser, you will see the request for login sent in the History tab. In following requests and responses you will find cookies. 

# Control

If the cookie-based session tokens do not have Secure attribute set, the control is failed.

# Resources

[https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

[https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies)