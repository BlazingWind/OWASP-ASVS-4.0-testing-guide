# 4.1.1 Client-side trust

> Verify that the application enforces access control rules on a trusted service layer, especially if client-side access control is present and could be bypassed.

CWE 602

# Explanation

This control encompasses any client-side access control. A proper way to enforce access control would be by duplicating checks that are made on client side, also on server-side. Even if there are access control checks on client-side, anything coming from the browser (the user) should not be trusted.

It's easiest to explain the control by an example - a user is presented with  a standard website (on presentation layer), which does not contain a link to admin panel. The fact that there is no direct link to the admin panel is the "access control" presented in the above requirements. But it is very easy to find the admin panel. Let's say it is found under "/admin-panel" and anyone is able to access it, as long as the person knows where it resides. An attacker may very easily find it by bruteforcing directories. 

The example application does not enforce access control rules on a trusted service layer (it enforces them on presentation layer), and the client-side access control can be bypassed.  

Another example: when trying to change a user's password the client side code checks if the user is authenticated, and then presents the user with the page for changing that user's password. But the server side does not check if the user is first authenticated and just processes the request to change the password. It essentially allows an attacker to change any user's password unless there are any other controls in place.

# Testing methods

Testing depends on what functionality a user is allowed in the application. Usually there are at least several sensitive actions that should first undergo an access control check, such as changing the password, making transactions, accessing sensitive files, writing comments in a private group in a social media app and more. Additionally, there should be controls that ensure that a user is not allowed to do any actions as another user.

Since above we have established which sensitive actions to look for, let's continue to where we can find them. For anything that requires a change (change of password, making transactions, writing comments) observe the traffic through a web proxy and look for POST requests.  Pay attention to the what is in the body of the request, but also look for what parameters are found in the URL. In addition you may use script 5-1-1 HTTP parameter pollution script in OWASP ZAP in connection with a spider.

## ZAP - bruteforcing directories

Choose the target website in the Sites tree > right-click choose Attack > Forced Browse Site. A new tab will open. Check that you have chosen the right site, then choose in the drop-down list "directory-list-1.0.txt". You may also add other directory bruteforcing lists such as SecLists in Options > Forced Browse. 

Additionally, refer to ZAP access control testing feature, which is described in the summary of the Access Control section.

# Control

Bruteforce directories of a target application and do a manual review of what was found. If there are any directories or areas such as admin panels that are not protected by access control, the control is failed. 

# Resources

[https://security.stackexchange.com/questions/196755/how-should-i-interpret-access-controls-on-the-presentation-layer-are-enforced](https://security.stackexchange.com/questions/196755/how-should-i-interpret-access-controls-on-the-presentation-layer-are-enforced)

[https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control](https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control)

[https://cheatsheetseries.owasp.org/IndexASVS.html#v4-access-control-verification-requirements](https://cheatsheetseries.owasp.org/IndexASVS.html#v4-access-control-verification-requirements)

[https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)