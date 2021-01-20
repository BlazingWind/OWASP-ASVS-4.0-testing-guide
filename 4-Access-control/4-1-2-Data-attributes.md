# 4.1.2 Data attributes

> Verify that all user and data attributes and policy information used by access controls cannot be manipulated by end users unless specifically authorized.

CWE 639

# Explanation

Sometimes access control is handled by a key value that a user has access to, such as a hidden field,  a value in a query parameter or an unencrypted cookie variable. The point of this control is to identify any parameters, cookies and form fields that could be used to bypass access control.

# Testing methods

## ZAP helper scripts

Enable script "4-1-2 Hidden fields.py" and "5-1-1 HTTP parameter pollution.py" and browse to the site in scope. Those scripts find most out in the application if you use it with a spider and active scan scripts when authenticated - but you may also manually login, fill out forms visible on the site and use all search fields. The first script searches html for hidden fields and raises an alert on any fields it has found. The second script looks for any parameters in URLs and in POST form fields and raises an alert on all parameters it has found. Review findings of the scripts. If there is an URL with parameter 'id' or a similar name, can you change its value and access areas that should not be accessible to an unauthenticated person? Review found query parameters and hidden fields in a similar way.

# Control

If any parameters, cookies and form fields that could be used to bypass access control, the control is failed.

# Resources

[https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)