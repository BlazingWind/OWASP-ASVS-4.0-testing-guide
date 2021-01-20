# 14.2.3 Subresource Integrity

> Verify that if application assets, such as JavaScript libraries, CSS stylesheets or web fonts, are hosted externally on a content delivery network (CDN) or external provider, Subresource Integrity (SRI) is used to validate the integrity of the asset.

CWE 714

# Explanation

Resources loaded from external providers should be checked against their hashes before they are loaded using subresource integrity. Any <script> and <link> elements should contain integrity attribute with a hash of the file and crossorigin attribute. 

SRI is used to check that a file that is loaded on a website has not been tampered with. SRI should be implemented on files loaded from a content delivery network. As an example - if an attacker controls a CDN, they may inject arbitrary content to the files that the target website is fetching. SRI will prevent such files from loading, since its hash would change.

The crossorigin attribute is used for making cross origin requests and loading Javascript files from another domain requires this attribute for SRI to function properly.

# Testing methods

## ZAP script

Enable script "14-2-3 Subresource Integrity" and browse to the site in scope. Preferably use a spider or and AJAX spider. The script searches for script and link elements and checks if integrity attribute is present for scripts and CSS loaded externally. If not present, it will raise an alert.

## Manually

SRI can be found in HTML. Using DevTools, inspect the html for all <script> and <link rel="stylesheet"> tags. Then look into Sources tab to see where are scripts and CSS files loaded from - knowing domains where scripts are loaded from will make it easier to find all loaded scripts in the HTML. If you see any loaded from places other than the target domain itself, see the names of the scripts. Back to Inspect tab and look in between <head> tags if the files are loaded against their hash.

Example of properly configured SRI:

```html
// Loading Javascript scripts
<script src="[https://example.com/example-framework.js](https://example.com/example-framework.js)"
integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
crossorigin="anonymous"></script>

// Loading CSS
<link rel="stylesheet" href="correct_hash.css" 
integrity="sha256-qvuZLpjL9TNV6yI1kNdGCPnSTrWM6Y0ILEzzyvA9hGY=">
```

If the hash is wrong or there is no crossorigin attribute, there will appear an error in the Console in Developer Tools. If not, the files will be loaded under Network tab with no error.

# Control

If there are files hosted externally e.g. on a CDN and they do not use SRI, the control is failed.

# Resources

[https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html)

[https://shubhamjain.co/til/subresource-integrity-crossorigin/](https://shubhamjain.co/til/subresource-integrity-crossorigin/)

[https://www.w3.org/TR/SRI/](https://www.w3.org/TR/SRI/)