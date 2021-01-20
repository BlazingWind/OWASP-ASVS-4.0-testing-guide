# 3.3.2 Re-authentication period

> If authenticators permit users to remain logged in, verify that re-authentication occurs periodically both when actively used or after an idle period. L1 - 30 days

CWE 613

Proactive Control C6

# Explanation

A user remaining logged gives a possibility to an attacker to be able to use a user's session without the need to know the password, e.g. if an attacker stole a work laptop that was left unlocked, the person will be able to use the application as the victim. Periodical re-authentication prevents this and many other attacks from happening. 

# Testing methods

Testing that re-authentication happens after 30 days may be tricky to work with. A cookie should however have an expiration date sent with every request. For tokens stored in local or session storage the situation is a bit more complicated, and the expiration time might not be set at all.

Tokens stored in LocalStorage do not expire, unless they are set with an expiration date - a time to live which can be set for example to 30 days (in seconds). The caveat is that the token does not get deleted after expiration time, but next time the user access the website. 

Tokens stored in SessionStorage get cleared after a user closes their browser; the expiration time for SessionStorage after a page session ends. Page session end happens when a tab is closed, a browser is closed or a new tab that creates another SessionStorage object is opened. As such, tokens stored here do require re-authentication. At last, SessionStorage is not as much used as LocalStorage.

If the reauthentication period is very short (e.g. 30 minutes) then the answer to the control failure  would show up during testing of the application, since the tester would have to log in again.

## ChromeDevTools

### Cookies

Identify the session cookie under Application > Cookies > target domain and look for its expiration date. 

### Tokens

Identify the session token under Application > LocalStorage > target domain, and look for the timestamp. If there is no timestamp on the session token, it means that it will be stored in the browser indefinitely.

# Control

If the expiration date is longer than 30 days, the control is failed.

# Resources

[https://blog.bitsrc.io/localstorage-sessionstorage-the-web-storage-of-the-web-6b7ca51c8b2a](https://blog.bitsrc.io/localstorage-sessionstorage-the-web-storage-of-the-web-6b7ca51c8b2a)

[https://stackoverflow.com/questions/13011944/make-localstorage-or-sessionstorage-expire-like-cookies?noredirect=1&lq=1](https://stackoverflow.com/questions/13011944/make-localstorage-or-sessionstorage-expire-like-cookies?noredirect=1&lq=1)

[https://www.w3schools.com/html/html5_webstorage.asp](https://www.w3schools.com/html/html5_webstorage.asp)

[https://stormpath.com/blog/where-to-store-your-jwts-cookies-vs-html5-web-storage](https://stormpath.com/blog/where-to-store-your-jwts-cookies-vs-html5-web-storage)