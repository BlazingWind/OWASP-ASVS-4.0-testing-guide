# 4.3.1 Admin MFA

> Verify administrative interfaces use appropriate multi-factor authentication to prevent unauthorized use.

CWE 419

# Explanation

Admin interfaces require particular protection against misuse.

# Testing methods

Even if admin interface is accessible on the internet, it is not possible to tell if all people that authenticate via it have MFA set. It requires an interview with the business owners and developers. 

# Control

If any admin does not use MFA for logging in, the control is failed. 

# Resources