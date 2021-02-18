# 14.2.1 Up to date components

> Verify that all components are up to date, preferably using a dependency checker during build or compile time.

CWE 1026

# Explanation

Using older versions of software packages, for example jQuery, may allow for exploitation of XSS on a website. This problem is also described in OWASP Top 10  "A9: Using Components with Known Vulnerabilities". The problem of using known vulnerable components is very spread, but essential to fix.

# Testing methods

There are several tools that can be used for checking dependencies such as OWASP dependency-check, Retire.js and many others. Consult [OWASP Cheat Sheet Vulnerable Dependency Management](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html) for more recommendations and best practices.

If the assessment is run without access to source code, only f.ex. on a website, you may use Retire.js. Retire.js has an extension to both Burp (only in Pro version) and ZAP, which will automatically detect issues.

If the assessment is done with access to source code, you may use OWASP dependency-checker. The tool contains several file type analyzers, which can be found under [https://jeremylong.github.io/DependencyCheck/analyzers/index.html](https://jeremylong.github.io/DependencyCheck/analyzers/index.html). It can be run as a command line tool or added to  your CI/CD pipeline.

## Proxy - RetireJS

Click the icon "Mange Add-ons" > choose tab "Marketplace" > filter for: "Retire.js" > check the tick in Retire.js entry > Click "Install selected". The plugin should work right away unless otherwise stated by the application. 

Browse to the site in scope. Preferably use a spider or and AJAX spider. The add-on will raise alerts with title "Vulnerable JS library" if there are any components that have known vulnerabilities.

If you would prefer to see the alerts as this ASVS control, you may use a standalone script "14-2-1 Up to date components.js". The script makes cosmetic changes to the alerts, in case the user would like to make a report which would only include ASVS controls - it changes the title to "14.2.1 Verify that all components are up to date, preferably using a dependency checker during build or compile time." and adds a description. Remember to run it only once - if you run it more than once, the same title and description will be appended again to the alert.

# Control

If any alerts were raised by RetireJS or any other dependency check tool, the control is failed.

# Resources

[OWASP Cheat Sheet Vulnerable Dependency Management](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html) 

[https://techbeacon.com/app-dev-testing/13-tools-checking-security-risk-open-source-dependencies](https://techbeacon.com/app-dev-testing/13-tools-checking-security-risk-open-source-dependencies)
