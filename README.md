# OWASP ASVS 4.0 testing guide

## Introduction

The OWASP ASVS 4.0 testing guide is an unofficial supporting document to the [OWASP Application Security Verification Standard](https://github.com/OWASP/ASVS) which attempts to describe each level 1 control, what are the consequences of not being compliant with it, how to test it - with known open source tools or manually - and the criteria for the control to be valid. Additionally, to several controls there have been developed scripts using bash or [OWASP ZAP](https://github.com/zaproxy/zaproxy) scripting engine to automate the check of said controls. The "ZAP-scripts" folder includes a guide on how to get started with ZAP scripts.

The aim of this project is to assist companies and organizations with getting started with using OWASP ASVS.

The project has been developed as part of my bachelor degree studies. 

## Download
[PDF version of OWASP ASVS 4.0 testing guide](https://github.com/BlazingWind/OWASP-ASVS-4.0-testing-guide/raw/main/OWASP-ASVS-testing-guide.pdf)
## Contributions

Contributions are welcome - please remember to use the format that the guide has been already using for each control, namely:

```markdown
# x.x.x Control title

> Control from ASVS
CWE number

## Explanation
What is the control all about - explain technical termns. 
Explain consequences of not being compliant with the control.

## User Stories and Scenarios
Have you written an associated User Story that can be used by teams to integrate the work relating to implementation of the control easier ? This supports both defining clear user stories as the scenarios which can be developed for testing

## Testing methods

If you know of already exisiting tools that could be used to test the control - either open source or that provide community edition - describe them here. 
Explain how to test the control manually, if possible.

## Control

Describe success criteria for the control. When can one deem the control failed?

## Resources
Provide additional links that expand on the topic or can make it easier to understand the control. If you can, link to a relevant OWASP Cheatsheet or a chapter from OWASP Web Security Testing Guide.
```
