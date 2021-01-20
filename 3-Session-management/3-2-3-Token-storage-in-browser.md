# 3.2.3 Token storage in browser

> Verify the application only stores session tokens in the browser using secure methods such as appropriately secured cookies (see section 3.4) or HTML 5 session storage.

CWE 539

# Explanation

In a longer discussion on their Github (see references) the ASVS creators have decided to change requirement 3.2.3 to mean that token-based session should only use SessionStorage, and not LocalStorage. Cookies will have their own requirements in section 3.4 and are not relevant for this control.

Tokens stored in LocalStorage do not expire, unless they are set with an expiration date. The caveat is that the token does not get deleted after expiration time, but next time the user access the website. 

Tokens stored in SessionStorage get cleared after a user closes their browser; the expiration time for SessionStorage is dependant on when the page session ends. Page session end happens when a tab is closed, a browser is closed or a new tab that creates another SessionStorage object is opened. As such, tokens stored here do require re-authentication. There have been many debates on using LocalStorage - from secure session management point of view, SessionStorage is considered more secure due to deletion of everything stored there, while LocalStorage allow for data to be stored indefinitely. As such OWASP does not recommend using LocalStorage for storing sensitive data, such as tokens.

# Testing methods

## ChromeDevTools

Search under Application > LocalStorage > target domain if there are any session tokens being stored.

# Control

If session tokens are stored under LocalStorage, the control is failed.

# Resources

[https://blog.gds-gov.tech/our-considerations-on-token-design-session-management-c2fa96198e6d](https://blog.gds-gov.tech/our-considerations-on-token-design-session-management-c2fa96198e6d)

[https://dev.to/rdegges/please-stop-using-local-storage-1i04](https://dev.to/rdegges/please-stop-using-local-storage-1i04)

[https://github.com/OWASP/ASVS/issues/696#issuecomment-626231907](https://github.com/OWASP/ASVS/issues/696#issuecomment-626231907)

[https://snyk.io/blog/is-localstorage-safe-to-use/](https://snyk.io/blog/is-localstorage-safe-to-use/)