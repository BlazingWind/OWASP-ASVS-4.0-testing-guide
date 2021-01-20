# 3.4.5 Cookie Path attribute

> Verify that if the application is published under a domain name with other applications that set or use session cookies that might override or disclose the session cookies, set the path attribute in cookie-based session tokens using the most precise path possible.

CWE 16

# Explanation

This is only applicable to domains that are published with several applications. Setting the Path attribute to be very precise will mitigate errors that might come form cookies being overridden.

It may be easier to present an example - a website having three applications that require login: a bank, a shop and a social media site. They would reside on:

example.com/bank

example.com/shop

example.com/socialmedia

Cookies for the bank would have a Path attribute set to /bank, shop to /shop, and the social media app to /socialmedia. This setup would prevent issues with cookie disclosure and errors.

# Testing methods

### Cookies

Log in to the application and go to Application tab > Cookies > choose the name of the target domain. Find the cookies used as session tokens and check their Path.

## ZAP

Similar to ChromeDevTools, you can look at the traffic in ZAP or other proxy. After logging in in a built in or preconfigured browser, you will see the request for login sent in the History tab. In following requests and responses you will find cookies.  

# Control

If an application is published under a domain with other applications and the cookies do not use precise Path, the control is failed.

# Resources

[https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#:~:text=The Path attribute indicates a,%2Fdocs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#:~:text=The%20Path%20attribute%20indicates%20a,%2Fdocs)

[https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

[https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies)