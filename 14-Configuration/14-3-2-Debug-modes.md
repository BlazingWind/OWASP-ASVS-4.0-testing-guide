# 14.3.2 Debug modes

> Verify that web or application server and application framework debug modes are disabled in production to eliminate debug features, developer consoles,  and unintended security disclosures.

CWE 497

# Explanation

Debug mode often allows for much more functionality and employs poorer security practices to make debugging easier. Therefore it should not be present in production.

# Testing methods

Debug code may not be visible right away.

## Proxy

Enable script "14-3-2 Debug modes.py" and browse to the site in scope. Preferably use a spider or and AJAX spider. The script searches the body of the response for words such as 'debug', 'medio' and raises an alert if it did find them.

Feel free to add to the script other words that software developers might have used for debugging. You may also use the Search tab to look for words which mean "debug" or similar  in the language of the website.

# Control

While it is preferable that no debug code is found, the control is not failed just because debug code was found. The point is that access to it should be disabled. For that, a short code review would need to be undertaken.

Conditions for success of this control are more flexible, but it is preferable that there is no debug code in production. If some is found, consider deleting it.

# Resources

[https://blog.pentesteracademy.com/hacking-jwt-tokens-debug-mode-in-production-4f8119b9b755](https://blog.pentesteracademy.com/hacking-jwt-tokens-debug-mode-in-production-4f8119b9b755)