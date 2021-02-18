# 14.2.2 Excess configuration removed

> Verify that all unneeded features, documentation, samples, configurations are removed, such as sample applications, platform documentation, and default or example users.

CWE 1002

# Explanation

Default configurations and code may contain users, credentials or open ports and overall lower security hardening, which is typically used for development.

# Testing methods

Based on information gained about the backend systems from other controls such as 14.2.1, 14.3.1 and 14.3.3 find default configuration for the component in its documentation. Afterwards check  whether it is present in the application.

## Proxy

If you have run other scripts, ZAP has possibly raised alerts on controls which show information disclosure (such as 14.2.1, 14.3.1 and 14.3.3 but also others). You can start by assessing the highlighted responses and then by using the Search tab.

# Control

This control is very dependent on the codebase and frameworks used. While having some default configuration is not bad by itself, ensure there are no default or example users, ports or unneeded code or documentation left. If any such information is found, the control is failed.