# 3.2.1 New session token on authentication

> Verify the application generates a new session token on user authentication.

CWE 384

Proactive Control C6

# Explanation

If a new session token is not generated on user authentication, then the session tokens can be reused. It is one of the fundamental requirements for a web application that session tokens are generated anew on each user authentication.

# Testing methods

## ChromeDevTools

### Cookies

Log in to the application and go to Application tab > Cookies > choose the name of the target domain. Note the session cookies being set - the name depends on application. For an application with PHP backend, it will probably be PHPSESSID. Usually they will be very easy to identify.

Log out and repeat the process. If you leave the ChromeDevTools open while logging in and out, you should see the cookies' values changing.

### Tokens

Follow the same flow, but look into the Network tab instead.  After logging in, you should see an Authorization header sent with every request. Log out and log in again. Observe if the Authorization header changed.

## ZAP

Similar to ChromeDevTools, you can look at the traffic in ZAP or other proxy. After logging in, you will see the request for login sent in the History tab. In following requests and responses there will be either the cookies or session tokens. Log out and log in again. Observe, if the session token has changed.

# Control

If the application does not set new session token on authentication, the control is failed. 

# Resources

[https://dev.to/thecodearcher/what-really-is-the-difference-between-session-and-token-based-authentication-2o39](https://dev.to/thecodearcher/what-really-is-the-difference-between-session-and-token-based-authentication-2o39)