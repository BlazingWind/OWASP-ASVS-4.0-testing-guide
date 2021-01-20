# 3.1.1 Session tokens in URLs

> Verify the application never reveals session tokens in URL parameters or error messages.

CWE 598

# Explanation

Due to the fact that URLs are usually recorded in logs, browser history and various other places, it increases the chances of them being captured by an attacker. Errors similarly will be stored in logs.  Revealing session tokens in URLs increases the risk and makes it easier for an attacker to launch an attack.

# Testing methods

## ZAP script

Enable script "3-1-1 Session token in URLs" and browse to the site in scope. Preferably use a spider or and AJAX spider. The script looks for the string 'token', 'jwt', 'session' and 'cookie' in the URL or in a error page. If it is found it raises an alert. Note that the script may produce false positives, and it is important to review its findings.

Additionally, you may run active rule script 14-3-1 for better coverage. This script attempts to trigger a few errors. 

# Control

If session token are found in the URL parameters or error pages, the control is failed.

# Resources
