# 3.4.3 Cookie SameSite attribute

> Verify that cookie-based session tokens utilize the 'SameSite' attribute to limit exposure to cross-site request forgery attacks.

CWE 16

Proactive Control C6

# Explanation

SameSite attribute has been implemented as protection against CSRF attacks. It can have one of three values: Strict, Lax and None. Strict means that the browser will never send a cookie with a cross-origin requests. Lax will send cookies with requests that user clicked on. None allows for sending cross origin requests, but only in secure contexts - it means that a cookie must also have Secure attribute set. This control requires that the cookie is set with either Strict or Lax.

In January 2020 Google Chrome has attempted to set all cookies in its browser with Strict attribute. Many enterprise websites have stopped working properly and Chrome reverted the change and introduced Lax value as a default value that a cookie will be set with, if no other value is set. Other browser vendors followed.

# Testing methods

### Cookies

Log in to the application and go to Application tab > Cookies > choose the name of the target domain. Find the cookies used as session tokens and check if they have the SameSite attribute set.

## ZAP

Similar to ChromeDevTools, you can look at the traffic in ZAP or other proxy. After logging in in a built in or preconfigured browser, you will see the request for login sent in the History tab. In following requests and responses you will find cookies.  

# Control

If the cookie-based session tokens do not have SameSite attribute set, the control is failed.

# Resources

[https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

[https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies)

[https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)

[https://medium.com/@renwa/bypass-samesite-cookies-default-to-lax-and-get-csrf-343ba09b9f2b](https://medium.com/@renwa/bypass-samesite-cookies-default-to-lax-and-get-csrf-343ba09b9f2b)