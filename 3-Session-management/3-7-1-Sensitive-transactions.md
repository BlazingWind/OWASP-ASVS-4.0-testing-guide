# 3.7.1 Sensitive transactions

> Verify the application ensures a valid login session or requires reauthentication or secondary verification before allowing any sensitive transactions or account modifications.

CWE 778

# Explanation

A session token may be stolen by an attacker and thus be used to perform fraudulent actions as the   victim. Having a secondary verification before commencing sensitive actions is a strong security preventive control that will help stop many attacks.

# Testing methods

Identify all areas which could be considered sensitive - making a payment or a wire transfer, changing a password or email, changing payments methods... and check if a user is presented with secondary verification.

# Control

If sensitive actions do not require secondary verification, the control is failed.

# Resources