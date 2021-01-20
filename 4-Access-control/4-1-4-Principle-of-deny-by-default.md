# 4.1.4 Principle of deny by default

> Verify that the principle of deny by default exists whereby new users/roles start with minimal or no permissions and users/roles do not receive access to new features until access is explicitly assigned.

CWE 276

Proactive Control C7

# Explanation

Principle of deny is an easy way to ensure that users have the least privileges possible. While the number of permissions or access rights will very from application to application, there should be a model defining what rights do new users have.

# Testing methods

Control 4.1.1 gives examples of sensitive actions and transactions. It is preferable to test this control via ZAP access control testing feature, which is described in the summary of the Access Control section, but it is also possible to check manually.

## Manually

Register a new user. Access all available resources and try out functionalities (transferring money, viewing messages, posting messages in a private group, viewing other user's files, uploading a file). The minimal functionality that a new user needs will vary depending on the web application's intentional use. From what you have observed try to answer>

- Was all the functionality that a new user was given required for using an application?
- Was the user given access to minimal files and resources?
- Was the user restricted from viewing other user's files, that they did not need to see?

For more ideas refer to WSTG,

# Control

If the principle of deny is not enforced, the control is failed. 

# Resources

[https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema.html](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema.html)