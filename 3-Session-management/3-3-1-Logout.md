# 3.3.1 Logout

> Verify that logout and expiration invalidate the session token, such that the back button or a downstream relying party does not resume an authenticated session, including across relying parties.

CWE 613

Proactive Control C6

# Explanation

Similarly to 3.2.1, where a new token should be generated on each user authentication, this control specifies that session tokens should be invalidated on logout, to prevent reusing session tokens. This is another fundamental requirement within session management.

# Testing methods

Log in, log out and try to use the back button. You should receive an error, if the token got invalidated. Bear in mind that if this action is successful, it may be due to insecure cache configuration. To be safe you may check the tokens with DevTools:

## ChromeDevTools

Log in to the application and open Application > Cookies > target domain. Find the cookies used for the session. Log out and observe whether the session cookies are deleted. If tokens are stored in WebStorage, follow the same process for Application > Local Storage > target domain and for Application > Session Storage > target domain.

# Control

If the logout or expiration does not invalidate the token, the control is failed.

# Resources