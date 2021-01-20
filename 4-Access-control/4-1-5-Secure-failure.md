# 4.1.5 Secure failure

> Verify that access controls fail securely including when an exception occurs.

CWE 285

Proactive Control C10

# Explanation

Default error pages usually disclose information about the underlying software running on the web server. Optimally instead of default error pages, there should be a custom, user-actionable error pages returned. 

# Testing methods

During the course of testing Access Control section, there probably were found directories, resources or areas of the target website, which are sensitive. Try to access them from an unauthenticated and authenticated user point of view. Take a few test cases, preferably having two user accounts:

- An authenticated user has access to a directory "target.com/personalportfolio". While being unauthenticated, try to access that directory.
- A website gives a possibility to upload a file as user A, which should be accessible only by user A. User B, knowing the URL and other information where the file is located, tries to view/edit the file.
- User A gives user B view rights to view a file user A owns. But then user A decides to revoke access to the file. User B tries to access the file after revocation.

There are many more similar situations and other situations in which a user a user should be presented with a generic error response. 

# Control

If access controls do not fail securely, the control is failed.

# Resources