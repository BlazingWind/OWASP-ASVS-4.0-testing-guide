# 3.4.2 Cookie HttpOnly attribute

> Verify that cookie-based session tokens have the 'HttpOnly' attribute set.

CWE 1004

Proactive Control C6

# Explanation

HttpOnly attribute makes a cookie inaccessible to Javascript, which helps mitigate XSS attacks. 

# Testing methods

### Cookies

Log in to the application and go to Application tab > Cookies > choose the name of the target domain. Find the cookies used as session tokens and check if they have the HttpOnly attribute set.

## ZAP

Similar to ChromeDevTools, you can look at the traffic in ZAP or other proxy. After logging in in a built in or preconfigured browser, you will see the request for login sent in the History tab. In following requests and responses you will find cookies.  

# Control

If the cookie-based session tokens do not have HttpOnly attribute set, the control is failed.

# Resources

[https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

[https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies)

[https://owasp.org/www-community/HttpOnly#:~:text=What is HttpOnly%3F,if the browser supports it](https://owasp.org/www-community/HttpOnly#:~:text=What%20is%20HttpOnly%3F,if%20the%20browser%20supports%20it)