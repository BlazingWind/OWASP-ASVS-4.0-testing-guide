You can contribute to the repo by writing ZAP scripts or by adding documentation to a control.

## ZED Attack Proxy scripts

If you are new to ZAP and HTTP proxies, check out the official ZAP how-to videos 

* [OWASP ZAP Deep dive](https://www.zaproxy.org/zap-deep-dive/) - longer, deep dive videos or
* [ZAP in ten](https://www.zaproxy.org/zap-in-ten/) - shorter introduction to quickly get started

In the links above you will also find guidance on how to get started with scripting. For a quick introduction, see the last five videos from [ZAP in ten series](https://www.zaproxy.org/zap-in-ten/) and go through the set up under [Getting Started with ZAP scripting](https://github.com/BlazingWind/OWASP-ASVS-4.0-testing-guide/blob/main/ZAP-scripts/Getting-Started-with-ZAP-scripting.pdf)

The easiest way to start scripting in ZAP is to copy one of the pre-existing scripts and change it to one's needs. Copy and tweak one of the scipts from this repository or from [ZAP community scripts](https://github.com/zaproxy/community-scripts).

## Control documentation

For documentation on testing controls, please remember to use the format that the guide has already been using for each control, namely:

```markdown
# x.x.x Control title

> Control from ASVS
CWE number

## Explanation
What is the control all about - explain technical terms. 
Explain consequences of not being compliant with the control.

## Testing methods

If you know of already exisiting tools that could be used to test the control - either open source or that provide community edition - describe them here. 
Explain how to test the control manually, if possible.

## Control

Describe success criteria for the control. When can one deem the control failed?

## Resources
Provide additional links that expand on the topic or can make it easier to understand the control. If you can, link to a relevant OWASP Cheatsheet or a chapter from OWASP Web Security Testing Guide.
