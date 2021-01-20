# 3.2.2 Session token entropy

> Verify that session tokens possess at least 64 bits of entropy.

CWE 331

Proactive Control C6

# Explanation

Session tokens with a small entropy leave the application open for bruteforcing/session guessing attacks. Assuming that a good Cryptographically Secure Pseudorandom Number Generator is used, the session token value can be estimated to have entropy half the length of the session token. A token 128 bits (16 bytes) in size would give around 64 bits of entropy. While there are cases in which entropy is calculated differently (see resources), for simplicity  assume that the length of a session ID should be at least 128 bits (16 bytes). To calculate entropy accurately, one would need a sample of 10 000 tokens to find the character list, to check whether the tokens use pre defined strings and if the random generator really is random. Be sure to check if the token is Base 64 encoded, since then the entropy will be calculated differently.

# Testing methods

## ChromeDevTools

### Cookies

Similarly to 3.2.1, log in and go to Application > Cookies > target domain and find session cookies. Log out and log in again, to see how much the cookies changed. If the application does not set the cookie randomly, you might see repeating strings in the cookie. To calculate the length of the cookie, you may use Python 3:

```python
$ python3
Python 3.8.2 
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> cookie = "DARFndj49sac-0bL6GWN5SdAFOdJTw-r4FvUBrE9O_bgPiBVKn7xkMjMUOluw_uBTa2R8fLHUDjnKmZ6Bh-3U746yLrAxeywReyIYv0U479JV9FH61b02wFzRlm6V-QxwSUdb0ZK4RsdirwpWaaEHmsc9D6ZHj5fvEjVw7XM"
>>> len(cookie)
168
```

### Tokens

Follow the same flow, but look into the Network tab instead.  After logging in, you should see an Authorization header sent with every request. If the token is a JWT, it does not make sense to calculate its entropy - in this case mark the control as N/A. 

## ZAP

Similar to ChromeDevTools, you can look at the traffic in ZAP or other proxy. After logging in, you will see the request for login sent in the History tab. In following requests and responses there will be either the cookies or session tokens. Log out and log in again. Observe, how much the session token has changed. 

# Control

If the session token is shorter than 128 bits or not randomly generated, the control is failed.

# Resources

[https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

[https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length](https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length)

[https://security.stackexchange.com/questions/138995/why-would-the-session-id-entropy-only-be-half-of-the-length-of-the-session-id](https://security.stackexchange.com/questions/138995/why-would-the-session-id-entropy-only-be-half-of-the-length-of-the-session-id)

[https://gist.github.com/4k1/6fbe670807db1d48407685d6cc46b0af](https://gist.github.com/4k1/6fbe670807db1d48407685d6cc46b0af)

[https://www.pleacher.com/mp/mlessons/algebra/entropy.html](https://www.pleacher.com/mp/mlessons/algebra/entropy.html)