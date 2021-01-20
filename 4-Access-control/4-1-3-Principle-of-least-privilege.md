# 4.1.3 Principle of least privilege

> Verify that the principle of least privilege exists - users should only be able to access functions, data files, URLs, controllers, services, and other resources, for which they possess specific authorization. This implies protection against spoofing and elevation of privilege.

CWE 285

Proactive Control C7

# Explanation

Oftentimes an application will have a strict authentication check, but some functionalities might not have a good authorization check. This control builds up on top of the previous two in the category and introduces the principle of least privilege, which says that users should only have access to functionality and files that enable them to do their work. 

Additionally, it may happen that documents or files that should only be for internal use of a company, are laid out in a way that a search engine is able to find it.

# Testing methods

Configure authentication in a context for a target website and use bruteforcing available in ZAP. The capabilities of the access control testing will make the testing also easier. Similar to 4.1.1, find sensitive functionality that may not enforce principle of least privilege. You may also want to interview developers or managers behind the application.

## ZAP - bruteforcing directories

Choose the target website in the Sites tree > right-click choose Attack > Forced Browse Site. A new tab will open. Check that you have chosen the right site, then choose in the drop-down list "directory-list-1.0.txt". You may also add other directory bruteforcing lists such as SecLists in Options > Forced Browse. 

## Robots.txt

Robots.txt is a file that is supposed to tell search engines and web crawls not to index specific subdirectories of a website. This file might give ideas as to what subdirectories might contain sensitive data. Try to access the listed directories and see if they should not be allowed to be accessed. If there are any wildcards as part of the disallowed entry, you may consider writing a script which would create a list for bruteforcing directories and use it with ZAP Forced Browse Site.

## Search engine dorks

Use search engine dorking to review whether the target websites leaks documents or files that were shared unintentionally to the outside. It may happen that you discover a directory that is unintentionally shared with the internet or discover a functionality that does not perform a precise authorization check. Usually you will find out information either about the backend or a misplaced document, which may give you ideas on how to write more specific dorks.

- Inurl dork will search for URLs containing a string `site:target.com`
- Site dork will only search within one site `inurl:login.php`
- Filetype or ext dork will display files with a specific extension `inurl:target.com filetype:pdf` try to use several different extensions to find out as much as you can about folders which may store sensitive documents - then try to access those folders and documents laying in them.
- By specifying a keyword to look for `inurl:target.com password` depending on which countries and which languages the site uses, you may want to use keywords like username and password in those languages.

Additionally, refer to ZAP access control testing feature, which is described in the summary of the Access Control section.

# Control

If principle of least privilege is not enforced, the control is failed.

# Resources

[https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)

[https://medium.com/nassec-cybersecurity-writeups/exploring-google-hacking-techniques-using-google-dork-6df5d79796cf](https://medium.com/nassec-cybersecurity-writeups/exploring-google-hacking-techniques-using-google-dork-6df5d79796cf)