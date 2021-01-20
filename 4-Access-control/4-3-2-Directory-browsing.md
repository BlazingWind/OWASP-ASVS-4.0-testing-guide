# 4.3.2 Directory browsing

> Verify that directory browsing is disabled unless deliberately desired. Additionally, applications should not allow discovery or disclosure of file or directory metadata, such as Thumbs.db, .DS_Store, .git or .svn folders.

CWE 548

# Explanation

Directory browsing is a way a server can display all its files instead of a webpage. When a browser requests a webpage, the web server returns an index file for a directory that the browser is trying to access and displays a webpage. If directory listing is turned on and the index file does not exist, the browser will instead display all its files that are available in the accessed directory. Currently directory listing is allowed only if the server is used as a file directory. The problem that comes with is that someone might either accidentally place there a sensitive file or forget to disable access to directory metadata. Recently, a very known misconfiguration is to leave .git file accessible on a web server - an attacker that obtains the .git file can reconstruct project's source. Leaving .git available to public is categorized as information disclosure. For modern web applications it is not usual to see a directory listing unless it is explicitly configured to show one.

Apache has had directory browsing of `/icons/` and `/icons/small/` enabled until recently, in which sysadmins placed sensitive files accidentally, which also lead to information disclosure.

# Testing methods

Usually directory browsing is enabled on root of the webserver "example.com/" .It may be enabled for one specific folder, but it would most likely require either manually requesting each subdirectory or using a spider and an already implemented ZAP passive rule:

## ZAP - passive rule

ZAP has a passive rule in Beta already implemented called Directory Browsing which detects directory listings, but only for Apache 2 (and nginx) and IIS 7.5. To use it, install in the Marketplace Passive Beta rules. Then navigate to Options > Passive Scan rules > set Threshold for Directory Browsing rule to Medium.

[https://www.zaproxy.org/docs/alerts/10033/](https://www.zaproxy.org/docs/alerts/10033/) 

Run standalone script "4-3-2 Directory browsing" if you'd like to update the title and description to match ASVS control for generating a report.

## ZAP bruteforcing

To test is files or folders such as .git, .svn  exist, you can quickly bruteforce all directories with Forced Browse feature in ZAP. After using the spider, right click on target application > Attack > 
Forced Browse Site. To test only bruteforcing these, create a short word list containing the three names and add it to ZAP wordlists via Options > Forced Browse.

# Control

If the directory browsing is enabled or any of the named files are accessible, the control is failed.

# Resources

[https://www.sciencedirect.com/topics/computer-science/directory-browsing](https://www.sciencedirect.com/topics/computer-science/directory-browsing)

[https://medium.com/swlh/hacking-git-directories-e0e60fa79a36](https://medium.com/swlh/hacking-git-directories-e0e60fa79a36)

[https://www.acunetix.com/blog/articles/directory-listing-information-disclosure](https://www.acunetix.com/blog/articles/directory-listing-information-disclosure)

[https://pentester.land/tutorials/2018/10/25/source-code-disclosure-via-exposed-git-folder.html](https://pentester.land/tutorials/2018/10/25/source-code-disclosure-via-exposed-git-folder.html)

[https://bugs.ghostscript.com/show_bug.cgi?id=695858](https://bugs.ghostscript.com/show_bug.cgi?id=695858)

[https://hackerone.com/reports/142549](https://hackerone.com/reports/142549)