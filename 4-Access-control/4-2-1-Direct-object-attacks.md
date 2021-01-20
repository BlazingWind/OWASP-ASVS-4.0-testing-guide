# 4.2.1 Direct object attacks

> Verify that sensitive data and APIs are protected against direct object attacks targeting creation, reading, updating and deletion of records, such as creating or updating someone else's record, viewing everyone's records, or deleting all records.

CWE 639

# Explanation

Insecure Direct Object References are vulnerabilities, which happen when files or internal implementation objects have a key value identifier that a user has access to, such as a hidden field,  a value in a query parameter or an unencrypted cookie variable. By changing a value in such a parameter and specifying a few other parameters, it may be possible to create, view or delete a record which a user has no authorization to. This control can be tested in conjunction with 4.1.1.

The only way to protect an application from IDORs is by using strict access control checks. At the same time, there are modern web frameworks, like Django, that do not have problems with this type of a vulnerability.

# Testing methods

Take an example vulnerable bank application, in which you can make a transfer. The transfer is made by sending a form in a POST request. 

```python
POST bank.com/transfer HTTP/1.1
...

fromAccount=1111&toAccount=2222&amount=100
```

If an attacker could perform a MiTM attack, the person could change the value to of "toAccount" to their own. 

Another example - a user want to update a file and the browser sends a request:

`bank.com/fileview?file=1234&action=update`

An attacker could craft a request to delete the file, although it does not belong to them:

`bank.com/fileview?file=1234&action=delete`

## ZAP helper scripts

Enable script "4-1-2 Hidden fields.py" and "5-1-1 HTTP parameter pollution.py" and browse to the site in scope. Those scripts find most out in the application if you use it with a spider and active scan scripts when authenticated - but you may also manually login, fill out forms visible on the site and use all search fields. The first script searches html for hidden fields and raises an alert on any fields it has found. The second script looks for any parameters in URLs and in POST form fields and raises an alert on all parameters it has found. Review findings of the scripts. If there is an URL with parameter 'id' or a similar name, can you change its value and access files that should not be accessible to an unauthenticated person? Review found query parameters and hidden fields in a similar way.

# Control

If it is possible to perform an IDOR on the web application, the control is failed.

# Resources

[https://www.acunetix.com/blog/web-security-zone/what-are-insecure-direct-object-references/](https://www.acunetix.com/blog/web-security-zone/what-are-insecure-direct-object-references/)

[https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References.html](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References.html)